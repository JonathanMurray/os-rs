use crate::util::{
    DirectoryEntry, Ecode, Fd, FilePermissions, FileStat, FileType, InodeIdentifier, OpenFileId,
    Pid, SysResult, Uid,
};
use crate::vfs::VirtualFilesystemSwitch;

use bitflags::bitflags;
use once_cell::sync::Lazy;

use std::collections::{hash_map, HashMap, LinkedList};
use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub struct ProcessWasKilledPanic;

// NOTE: Take care when using this!
// 1. Don't hold onto this lock while using the VFS. ProcFS may block
// waiting for the lock to be released.
// 2. Don't claim this lock without having locked System first.
// Otherwise another process could be holding the System lock and
// block on this one.
pub static GLOBAL_PROCESS_TABLE: Lazy<Mutex<GlobalProcessTable>> = Lazy::new(|| {
    Mutex::new(GlobalProcessTable {
        next_pid: Pid(0),
        processes: Default::default(),
        currently_running_pid: None,
    })
});

pub static GLOBAL_PROCESS_SPAWN_QUEUE: Lazy<Mutex<LinkedList<ProcessHandle>>> =
    Lazy::new(Default::default);

/// stdin, stdout, stderr
type StandardFds = (
    Option<Arc<OpenFileId>>,
    Option<Arc<OpenFileId>>,
    Option<Arc<OpenFileId>>,
);

#[derive(Debug)]
pub struct GlobalProcessTable {
    next_pid: Pid,
    processes: HashMap<Pid, Process>,
    currently_running_pid: Option<Pid>,
}

impl GlobalProcessTable {
    fn add(
        &mut self,
        args: Vec<String>,
        parent_pid: Pid,
        uid: Uid,
        fds: StandardFds,
        cwd: InodeIdentifier,
    ) -> Pid {
        let pid = self.next_pid;
        let process = Process::new(pid, parent_pid, uid, args, fds, cwd);
        self.next_pid = Pid(self.next_pid.0 + 1);
        self.processes.insert(pid, process);
        pid
    }

    fn reap(&mut self, pid: Pid) {
        self.processes
            .remove(&pid)
            .expect("Cannot remove process. Unrecognized pid");
    }

    pub fn process(&mut self, pid: Pid) -> Option<&mut Process> {
        self.processes.get_mut(&pid)
    }

    fn children_mut(&mut self, parent_pid: Pid) -> impl Iterator<Item = &mut Process> {
        self.processes
            .values_mut()
            .filter(move |p| p.parent_pid == parent_pid)
    }

    pub fn current(&mut self) -> &mut Process {
        let pid = self.currently_running_pid.expect("No current pid");
        self.processes.get_mut(&pid).unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Process> {
        self.processes.values()
    }

    pub fn count(&self) -> usize {
        self.processes.len()
    }
}

#[derive(Debug, PartialEq)]
pub enum ProcessResult {
    ExitCode(u32),
    Killed(Signal),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    Kill,
    Interrupt,
    ChildTerminated,
}

pub trait SignalHandler: Send + std::fmt::Debug {
    fn handle(&self, signal: Signal);
}

#[derive(Debug)]
pub struct Process {
    pub pid: Pid,
    pub parent_pid: Pid,
    pub uid: Uid,
    pub args: Vec<String>,
    // should this _actually_ be called "open_files" instead?
    // the key is the Fd, and the value (on Linux) is actually
    // a _pointer_ to an "open file" structure, not an ID (?)
    pub fds: HashMap<Fd, Arc<OpenFileId>>,
    next_fd: Fd,
    cwd: InodeIdentifier,
    pub log: Vec<String>,
    pub state: ProcessState,

    result: Option<ProcessResult>,
    pending_signals: LinkedList<Signal>,
}

impl Process {
    fn new(
        pid: Pid,
        parent_pid: Pid,
        uid: Uid,
        args: Vec<String>,
        fds: StandardFds,
        cwd: InodeIdentifier,
    ) -> Self {
        let mut next_fd = 0;
        let mut fd_map = HashMap::new();
        if let Some(stdin) = fds.0 {
            fd_map.insert(0, stdin);
            next_fd = 1;
        }
        if let Some(stdout) = fds.1 {
            fd_map.insert(1, stdout);
            next_fd = 2;
        }
        if let Some(stderr) = fds.2 {
            fd_map.insert(2, stderr);
            next_fd = 3;
        }
        Process {
            pid,
            parent_pid,
            uid,
            args,
            fds: fd_map,
            next_fd,
            cwd,
            log: vec![],
            state: ProcessState::Running,
            result: None,
            pending_signals: Default::default(),
        }
    }

    fn duplicate_fd(&mut self, old_fd: Fd) -> Option<Fd> {
        if let Some(open_file_id) = self.fds.get(&old_fd) {
            let new_fd = self.next_fd;
            let cloned_ref = Arc::clone(open_file_id);
            self.fds.insert(new_fd, cloned_ref);
            self.next_fd += 1;
            return Some(new_fd);
        }
        None
    }

    fn add_open_file(&mut self, open_file_id: Arc<OpenFileId>) -> Fd {
        let fd = self.next_fd;
        eprintln!("{:?} adding {:?} => {:?}", self.pid, fd, open_file_id);
        self.fds.insert(fd, open_file_id);
        self.next_fd += 1;
        fd
    }

    fn insert_open_file(&mut self, fd: Fd, open_file_id: Arc<OpenFileId>) -> bool {
        match self.fds.entry(fd) {
            hash_map::Entry::Vacant(e) => {
                e.insert(open_file_id);
                true
            }
            hash_map::Entry::Occupied(_) => false,
        }
    }

    fn find_open_file(&mut self, fd: Fd) -> SysResult<OpenFileId> {
        self.fds.get(&fd).map(|x| *x.as_ref()).ok_or(Ecode::Ebadf)
    }

    fn cloned_open_file(&mut self, fd: Fd) -> Option<Arc<OpenFileId>> {
        self.fds.get(&fd).map(Arc::clone)
    }

    fn take_open_file(&mut self, fd: Fd) -> Option<Arc<OpenFileId>> {
        self.fds.remove(&fd)
    }

    fn take_fds(&mut self) -> HashMap<Fd, Arc<OpenFileId>> {
        std::mem::take(&mut self.fds)
    }

    fn ensure_zombie(&mut self, result: ProcessResult) {
        // Don't override existing result if process is already a zombie
        self.result.get_or_insert(result);
        self.state = ProcessState::Zombie;
    }

    fn zombify(&mut self, result: ProcessResult) {
        assert!(
            self.result.is_none(),
            "{:?}: Can't set result to {:?}. It is already set to {:?}",
            self.pid,
            result,
            self.result
        );
        assert!(self.state != ProcessState::Zombie);
        eprintln!("{:?}: Setting result to {:?}", self.pid, result);
        self.ensure_zombie(result);
    }

    // TODO: feels iffy that this is public. Used from devfs
    pub fn signal(&mut self, signal: Signal) {
        self.pending_signals.push_front(signal);
        eprintln!(
            "DEBUG: pushed signal to pending signal queue: {:?}",
            self.pending_signals
        );
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ProcessState {
    Running,
    Waiting,
    Zombie,
}

#[derive(Debug)]
pub struct System {
    pub vfs: VirtualFilesystemSwitch,
}

impl System {
    pub fn new(vfs: VirtualFilesystemSwitch) -> Self {
        Self { vfs }
    }

    pub fn spawn_process(
        mut processes: MutexGuard<'_, GlobalProcessTable>,
        sys: Arc<Mutex<System>>,
        args: Vec<String>,
        parent_pid: Pid,
        uid: Uid,
        fds: StandardFds,
        cwd: InodeIdentifier,
    ) -> ProcessHandle {
        let pid = processes.add(args, parent_pid, uid, fds, cwd);
        ProcessHandle {
            shared_sys: sys,
            pid,
            signal_handlers: Default::default(),
            has_died: AtomicBool::new(false),
        }
    }

    fn close_files(&mut self, open_files: impl Iterator<Item = Arc<OpenFileId>>) {
        for open_file_id in open_files {
            self.vfs.close_file(open_file_id);
        }
    }
}

#[derive(Debug)]
pub struct ProcessHandle {
    // Prefer to use sys from ActiveProcessHandle
    // to avoid potential deadlocks
    shared_sys: Arc<Mutex<System>>,
    pid: Pid,
    signal_handlers: Mutex<HashMap<Signal, Box<dyn SignalHandler>>>,

    // Used to ensure that we don't interact with the handle after
    // the process has exited. That could happen if a process is
    // killed while holding onto a RAII (like FileReader) which
    // would try to close FD's after the process has already been
    // removed from the global process table.
    has_died: AtomicBool,
}

impl ProcessHandle {
    pub fn clone_args(&self) -> Vec<String> {
        let active_handle = ActiveProcessHandle::new(self);
        let mut processes = active_handle.process_table();
        processes.current().args.clone()
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn has_died(&self) -> bool {
        self.has_died.load(Ordering::Relaxed)
    }

    pub fn sc_nanosleep(&self, duration: Duration) -> SysResult<()> {
        let end = Instant::now() + duration;

        while Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
            let active_handle = ActiveProcessHandle::new(self);
            if self._handle_signals(active_handle) {
                // Receiving a signal interrupts the syscall
                return Err(Ecode::Eintr);
            }
        }

        Ok(())
    }

    pub fn sc_pipe(&self) -> SysResult<(Fd, Fd)> {
        let mut active_handle = ActiveProcessHandle::new(self);
        {
            let mut processes = active_handle.process_table();
            let current_proc = processes.current();
            current_proc.log.push("pipe()".to_owned());
        }
        //Release process lock before using VFS

        let (read_open_file_id, write_open_file_id) = active_handle.sys.vfs.create_pipe();

        eprintln!(
            "DEBUG: in sc_pipe, strong counts: read={}, write={}",
            Arc::strong_count(&read_open_file_id),
            Arc::strong_count(&write_open_file_id)
        );

        let mut processes = active_handle.process_table();
        let current_proc = processes.current();
        let read_fd = current_proc.add_open_file(read_open_file_id);
        let write_fd = current_proc.add_open_file(write_open_file_id);
        Ok((read_fd, write_fd))
    }

    pub fn sc_sigaction(&self, signal: Signal, handler: Box<dyn SignalHandler>) {
        let active_handle = ActiveProcessHandle::new(self);
        {
            let mut processes = active_handle.process_table();
            let current_proc = processes.current();
            current_proc
                .log
                .push(format!("sigaction({:?}, <handler>)", signal));
        }
        self.signal_handlers.lock().unwrap().insert(signal, handler);
        //https://man7.org/linux/man-pages/man2/sigaction.2.html
        //int sigaction(int signum, const struct sigaction *restrict act,
        //             struct sigaction *restrict oldact);
    }

    pub fn handle_signals(&self) {
        let active_handle = ActiveProcessHandle::new(self);
        self._handle_signals(active_handle);
    }

    fn _handle_signals(&self, mut active_handle: ActiveProcessHandle) -> bool {
        let mut processes = active_handle.process_table();
        let process = processes.current();
        if let Some(signal) = process.pending_signals.pop_back() {
            if let Some(handler) = self.signal_handlers.lock().unwrap().get(&signal) {
                // Drop locks before invoking custom handler, to avoid deadlock
                drop(processes);
                drop(active_handle);
                handler.handle(signal);
            } else {
                match signal {
                    Signal::Kill | Signal::Interrupt => {
                        process.zombify(ProcessResult::Killed(signal));
                        self.has_died.store(true, Ordering::Relaxed);

                        let fds = process.take_fds().into_values();

                        let parent_pid = process.parent_pid;
                        let parent = processes.process(parent_pid).expect("Parent must exist");
                        parent.signal(Signal::ChildTerminated);

                        //Release process lock before using VFS
                        drop(processes);
                        active_handle.sys.close_files(fds);
                        drop(active_handle);
                        // Drop before panic, so we don't poison locks
                        eprintln!("Panicking due to process killed in handle_signals");
                        std::panic::panic_any(ProcessWasKilledPanic);
                    }
                    Signal::ChildTerminated => {
                        // Default action is to ignore
                    }
                }
            }
            return true;
        }
        false
    }

    pub fn stdout(&self, s: impl Display) -> SysResult<()> {
        let output = format!("{}", s);
        let n_written = self.sc_write(1, output.as_bytes())?;
        assert_eq!(
            n_written,
            output.len(),
            "We didn't write all the output to stdout"
        );
        Ok(())
    }

    pub fn stderr(&self, s: impl Display) -> SysResult<()> {
        let output = format!("{}", s);
        let n_written = self.sc_write(2, output.as_bytes())?;
        assert_eq!(
            n_written,
            output.len(),
            "We didn't write all the output to stdout"
        );
        Ok(())
    }

    pub fn sc_getpid(&self) -> Pid {
        let active_handle = ActiveProcessHandle::new(self);
        let mut processes = active_handle.process_table();
        processes.current().log.push("getpid()".to_owned());
        self.pid
    }

    pub fn sc_spawn(
        &self,
        args: Vec<String>,
        fds: SpawnFds,
        uid: SpawnUid,
        action: Option<SpawnAction>,
    ) -> SysResult<Pid> {
        let child_handle = {
            let self_pid = self.pid;
            let child_sys = self.shared_sys.clone();

            let active_handle = ActiveProcessHandle::new(self);
            let mut processes = active_handle.process_table();
            let current_proc = processes.current();
            current_proc.log.push(format!(
                "spawn({:?}, {:?}, {:?}, {:?})",
                args, fds, uid, action
            ));

            let (stdin, stdout, stderr) = match fds {
                SpawnFds::Inherit => (
                    current_proc.cloned_open_file(0),
                    current_proc.cloned_open_file(1),
                    current_proc.cloned_open_file(2),
                ),
                SpawnFds::Set(stdin, stdout, stderr) => (
                    current_proc.cloned_open_file(stdin),
                    current_proc.cloned_open_file(stdout),
                    current_proc.cloned_open_file(stderr),
                ),
            };
            let child_uid = match uid {
                SpawnUid::Inherit => current_proc.uid,
                SpawnUid::Uid(uid) => uid,
            };
            eprintln!(
                "Spawning {:?}. Stdin={:?}, Stdout={:?}, Uid={:?}",
                args, stdin, stdout, uid
            );
            eprintln!("(Current proc open files: {:?})", current_proc.fds);
            let cwd = current_proc.cwd;
            System::spawn_process(
                processes,
                child_sys,
                args,
                self_pid,
                child_uid,
                (stdin, stdout, stderr),
                cwd,
            )
        };
        let child_pid = child_handle.pid;
        eprintln!("Spawned pid={:?}", child_pid);

        if let Some(SpawnAction::ClaimTerminal(terminal_fd)) = action {
            let mut active_handle = ActiveProcessHandle::new(self);
            let mut processes = active_handle.process_table();
            let current_proc = processes.current();

            let open_file_id = current_proc.find_open_file(terminal_fd)?;

            //Release process lock before using VFS
            drop(processes);
            active_handle.sys.vfs.ioctl(
                open_file_id,
                IoctlRequest::SetTerminalForegroundProcess(child_pid),
            );
        }

        let mut spawn_queue = GLOBAL_PROCESS_SPAWN_QUEUE.lock().unwrap();
        spawn_queue.push_front(child_handle);

        Ok(child_pid)
    }

    pub fn sc_exit(self, code: u32) {
        let mut active_handle = ActiveProcessHandle::new(&self);
        let mut processes = active_handle.process_table();
        let proc = processes.current();
        proc.log.push(format!("exit({})", code));
        proc.zombify(ProcessResult::ExitCode(code));
        self.has_died.store(true, Ordering::Relaxed);

        let fds = proc.take_fds().into_values();

        let parent_pid = proc.parent_pid;
        let parent = processes.process(parent_pid).expect("Parent must exist");
        parent.signal(Signal::ChildTerminated);

        // Release process lock before using VFS
        drop(processes);
        active_handle.sys.close_files(fds);
    }

    pub fn sc_wait_pid(
        &self,
        target: WaitPidTarget,
        options: WaitPidOptions,
    ) -> SysResult<Option<(Pid, ProcessResult)>> {
        let self_pid = self.pid;
        {
            let active_context = ActiveProcessHandle::new(self);
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.state = ProcessState::Waiting;
            proc.log
                .push(format!("wait_pid({:?}, {:?})", target, options));
        }
        //Release all locks before sleeping
        loop {
            //TODO: Don't busy-wait. Yield control to scheduler somehow.
            std::thread::sleep(Duration::from_millis(20));

            let active_context = ActiveProcessHandle::new(self);
            let mut processes = active_context.process_table();
            let child_and_result = match target {
                WaitPidTarget::Pid(pid) => {
                    let child = processes.process(pid).expect("Child process must exist");
                    child.result.take().map(|result| (pid, result))
                }
                WaitPidTarget::AnyChild => {
                    let mut found = None;
                    for child in processes.children_mut(self_pid) {
                        if let Some(result) = child.result.take() {
                            found = Some((child.pid, result));
                            break;
                        }
                    }
                    found
                }
            };
            if let Some((child_pid, child_result)) = child_and_result {
                eprintln!("{:?} will reap {:?}", self_pid, child_pid);
                processes.reap(child_pid);
                processes.current().state = ProcessState::Running;
                return Ok(Some((child_pid, child_result)));
            } else if options == WaitPidOptions::NoHang {
                processes.current().state = ProcessState::Running;
                return Ok(None);
            }
            drop(processes);

            if self._handle_signals(active_context) {
                // Receiving a signal interrupts the syscall
                return Err(Ecode::Eintr);
            }
        }
    }

    pub fn sc_kill(&self, pid: Pid, signal: Signal) -> SysResult<()> {
        let active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let current_proc = processes.current();
        let self_uid = current_proc.uid;
        current_proc.log.push(format!("kill({:?})", pid));
        if active_context.pid == pid {
            return Err(Ecode::Custom("Cannot kill self".to_owned()));
        }
        let victim_proc = processes.process(pid).ok_or(Ecode::Esrch)?;
        //TODO can a process kill its parent? It doesn't seem to work
        //when a subshell tries to kill the parent shell
        if victim_proc.uid != self_uid {
            return Err(Ecode::Eperm);
        }
        victim_proc.signal(signal);
        Ok(())
    }

    pub fn sc_create<S: Into<String>>(
        &self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let path = path.into();

        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("create({:?})", path));
        let cwd = proc.cwd;

        // Release process lock before using VFS
        drop(processes);

        active_context
            .sys
            .vfs
            .create_file(path, file_type, permissions, cwd)
    }

    pub fn sc_open(
        &self,
        path: &str,
        flags: OpenFlags,
        creation_file_permissions: Option<FilePermissions>,
    ) -> SysResult<Fd> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!(
            "open({:?}, {:?}, {:?})",
            path, flags, creation_file_permissions
        ));
        let cwd = proc.cwd;
        // Release process lock before using VFS
        drop(processes);

        let vfs = &mut active_context.sys.vfs;

        let open_file_id = vfs.open_file(path, cwd, flags, creation_file_permissions)?;

        let mut processes = active_context.process_table();
        let proc = processes.current();
        let fd = proc.add_open_file(open_file_id);

        Ok(fd)
    }

    pub fn sc_close(&self, fd: Fd) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("close({})", fd));
        let open_file_id = proc.take_open_file(fd).ok_or(Ecode::Ebadf)?;
        eprintln!(
            "In sc_close: Closing fd {} with open_file_id: {:?}",
            fd, open_file_id
        );

        // Release process lock before using VFS
        drop(processes);

        //BUG: This should only remove the file
        //from the file description table, if there are no
        //remaining references to it

        active_context.sys.vfs.close_file(open_file_id);
        Ok(())
    }

    pub fn sc_stat(&self, path: &str) -> SysResult<FileStat> {
        let mut active_context = ActiveProcessHandle::new(self);
        let cwd = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push(format!("stat({:?})", path));
            proc.cwd
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.stat_file(path, cwd)
    }

    pub fn sc_ioctl(&self, fd: Fd, req: IoctlRequest) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("ioctl({:?})", req));
        let open_file_id = proc.find_open_file(fd)?;
        // Release process lock before using VFS
        drop(processes);

        active_context.sys.vfs.ioctl(open_file_id, req);
        Ok(())
    }

    pub fn sc_getdents(&self, fd: Fd) -> SysResult<Vec<DirectoryEntry>> {
        let mut active_context = ActiveProcessHandle::new(self);
        let open_file_id = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push(format!("getdents({})", fd));
            proc.find_open_file(fd)?
        };

        // unlock process table before calling VFS
        Ok(active_context.sys.vfs.list_dir(open_file_id))
    }

    pub fn sc_read(&self, fd: Fd, buf: &mut [u8]) -> SysResult<usize> {
        let mut active_context = ActiveProcessHandle::new(self);

        let open_file_id = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push(format!("read({}, buf)", fd));
            proc.find_open_file(fd)?
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.read_file(open_file_id, buf)
    }

    pub fn sc_write(&self, fd: Fd, buf: &[u8]) -> SysResult<usize> {
        //TODO permissions
        //
        let mut active_context = ActiveProcessHandle::new(self);

        let open_file_id = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log
                .push(format!("write({}, <{} bytes>)", fd, buf.len()));

            proc.find_open_file(fd)?
        };

        // unlock process table before calling VFS
        let num_written = active_context.sys.vfs.write_file(open_file_id, buf)?;
        Ok(num_written)
    }

    pub fn sc_sendfile(&self, out_fd: Fd, in_fd: Fd, count: usize) -> SysResult<usize> {
        let mut active_context = ActiveProcessHandle::new(self);
        let (in_file_id, out_file_id) = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log
                .push(format!("sendfile({:?}, {:?}, {}))", out_fd, in_fd, count));

            (proc.find_open_file(in_fd)?, proc.find_open_file(out_fd)?)
        };

        let mut buf = vec![0; count];

        let n_read = active_context.sys.vfs.read_file(in_file_id, &mut buf)?;
        let n_written = active_context
            .sys
            .vfs
            .write_file(out_file_id, &buf[0..n_read])?;

        assert_eq!(
            n_read, n_written,
            "Not all data was written. We need to handle this!"
        );

        Ok(n_read)
    }

    pub fn sc_seek(&self, fd: Fd, offset: SeekOffset) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("seek({}, {:?})", fd, offset));
        let open_file_id = proc.find_open_file(fd)?;

        // unlock process table before calling VFS
        drop(processes);
        active_context.sys.vfs.seek(open_file_id, offset)
    }

    pub fn sc_chdir<S: Into<String>>(&self, path: S) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let path = path.into();
        let cwd = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push(format!("chdir({:?})", path));
            proc.cwd
        };

        // unlock process table before calling VFS
        let new_cwd_inode = active_context.sys.vfs.resolve_directory(&path, cwd)?;

        let cwd = new_cwd_inode.id;
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.cwd = cwd;
        Ok(())
    }

    // The syscall getcwd requires you to pass in a buffer that
    // will hold the dir name.
    pub fn get_current_dir_name(&self) -> SysResult<String> {
        let mut active_context = ActiveProcessHandle::new(self);
        let cwd = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push("get_current_dir_name()".to_owned());
            proc.cwd
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.path_from_inode(cwd).map_err(|e| {
            eprintln!("WARN: get_current_dir_name error: {}", e);
            Ecode::Enoent
        })
    }

    pub fn sc_unlink(&self, path: &str) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let cwd = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push(format!("remove({:?})", path));
            proc.cwd
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.unlink_file(path, cwd)
    }

    pub fn sc_rename<S: Into<String>>(&self, old_path: &str, new_path: S) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let new_path = new_path.into();
        let cwd = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log
                .push(format!("rename({:?}, {:?})", old_path, new_path));
            proc.cwd
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.rename_file(old_path, new_path, cwd)
    }

    pub fn sc_dup(&self, oldfd: Fd) -> SysResult<Fd> {
        let active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("dup({:?})", oldfd));

        proc.duplicate_fd(oldfd).ok_or(Ecode::Ebadf)
    }

    pub fn sc_dup2(&self, oldfd: Fd, newfd: Fd) -> SysResult<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("dup2({:?}, {:?})", oldfd, newfd));

        let dst_open_file_id = proc.take_open_file(newfd);

        drop(processes);
        // unlock process table before calling VFS

        if let Some(open_file_id) = dst_open_file_id {
            active_context.sys.vfs.close_file(open_file_id);
        }

        let mut processes = active_context.process_table();
        let proc = processes.current();

        let cloned_open_file_id = proc.cloned_open_file(oldfd).ok_or(Ecode::Ebadf)?;
        if proc.insert_open_file(newfd, cloned_open_file_id) {
            Ok(())
        } else {
            Err(Ecode::Custom("failed to insert fd".to_owned()))
        }
    }
}

impl Drop for ProcessHandle {
    /// Clean up any remaining resources. This may effectively be a no-op
    /// depending on how the process exited.
    fn drop(&mut self) {
        let pid = self.pid;
        let mut sys = match self.shared_sys.lock() {
            Ok(sys) => sys,
            Err(_) => {
                println!("CRITICAL ERROR: System lock was poisoned");
                // We return to avoid clogging the stderr with a poison stacktrace.
                // We just want to see the root cause in the logs.
                return;
            }
        };

        eprintln!("{:?} getting processes in ProcessHandle::drop", pid);

        // LOCKING: We have locked System above
        let mut processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
        eprintln!("{:?} got processes in ProcessHandle::drop", pid);

        if let Some(p) = processes.process(pid) {
            p.ensure_zombie(ProcessResult::ExitCode(0));
            let fds = p.take_fds();
            eprintln!("Dropping process {:?}. Will close fds: {:?}", pid, fds);
            // Release process lock before using VFS
            drop(processes);
            sys.close_files(fds.into_values());
        } else {
            eprintln!("Process has already been reaped");
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum WaitPidTarget {
    Pid(Pid),
    AnyChild,
}

#[derive(Debug, PartialEq)]
pub enum WaitPidOptions {
    Default,
    NoHang,
}

#[derive(Debug)]
pub enum SpawnFds {
    Inherit,
    Set(Fd, Fd, Fd),
}

#[derive(Debug)]
pub enum SpawnUid {
    Inherit,
    Uid(Uid),
}

#[derive(Debug)]
pub enum SpawnAction {
    ClaimTerminal(Fd),
}

#[derive(Debug)]
pub enum IoctlRequest {
    SetTerminalForegroundProcess(Pid),
}

bitflags! {
    pub struct OpenFlags: u8 {
        const CREATE  = 0b0000_0001;
        const TRUNCATE  = 0b0000_0010;
        const READ_ONLY = 0b0000_0100;
        const WRITE_ONLY = 0b0000_1000;
        const READ_WRITE = 0b0001_0000;
    }
}

#[derive(Debug)]
pub enum SeekOffset {
    Set(usize),
    End(i64),
}

struct ActiveProcessHandle<'a> {
    pid: Pid,
    sys: MutexGuard<'a, System>,
}

impl<'a> ActiveProcessHandle<'a> {
    fn new(handle: &'a ProcessHandle) -> Self {
        let sys = handle.shared_sys.lock().unwrap();

        // LOCKING: We have locked System above
        let mut processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
        assert!(
            processes.currently_running_pid.is_none(),
            "Another process is already active"
        );
        assert!(
            processes.process(handle.pid).is_some(),
            "Can't activate process {:?}. It doesn't exist",
            handle.pid
        );

        processes.currently_running_pid = Some(handle.pid);
        //eprintln!("DEBUG: running: {}", handle.pid);

        ActiveProcessHandle {
            pid: handle.pid,
            sys,
        }
    }

    //TODO: how to prevent this being called twice? Should it take a &mut self?
    fn process_table(&self) -> MutexGuard<'_, GlobalProcessTable> {
        // LOCKING: System is locked - we own a MutexGuard
        GLOBAL_PROCESS_TABLE.lock().unwrap()
    }
}

impl Drop for ActiveProcessHandle<'_> {
    fn drop(&mut self) {
        //eprintln!(
        //    "DEBUG: {} Getting processes in ActiveProcessHandler::drop",
        //    self.pid
        //);
        let mut processes = self.process_table();
        //println!(
        //   "DEBUG: {} Got processes in ActiveProcessHandler::drop",
        //   self.pid
        //;
        assert!(
            processes.currently_running_pid.is_some(),
            "This process is not marked as active"
        );
        processes.currently_running_pid = None;
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::util::FilesystemId;

    // Can't run tests in parallel, as they all spawn processes from a new
    // System. When running the OS normally, there is exactly one System.
    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn setup() -> ProcessHandle {
        let vfs = VirtualFilesystemSwitch::new();
        let sys = System::new(vfs);
        System::spawn_process(
            GLOBAL_PROCESS_TABLE.lock().unwrap(),
            Arc::new(Mutex::new(sys)),
            vec!["test".to_owned()],
            Pid(1),
            Uid(1),
            (None, None, None),
            InodeIdentifier {
                filesystem_id: FilesystemId::Main,
                number: 0,
            },
        )
    }

    #[test]
    fn creating_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let ctx = setup();
        ctx.sc_create("/myfile", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();
    }

    #[test]
    fn creating_files_and_listing_them() {
        let _lock = TEST_LOCK.lock().unwrap();
        let ctx = setup();
        ctx.sc_create("/mydir", FileType::Directory, FilePermissions::new(7, 7))
            .unwrap();
        ctx.sc_create(
            "/mydir/subdir",
            FileType::Directory,
            FilePermissions::new(7, 7),
        )
        .unwrap();
        ctx.sc_create(
            "/mydir/file_in_dir",
            FileType::Regular,
            FilePermissions::new(7, 7),
        )
        .unwrap();
        ctx.sc_create(
            "/mydir/subdir/file_in_subdir",
            FileType::Regular,
            FilePermissions::new(7, 7),
        )
        .unwrap();

        assert_eq!(
            list_dir(&ctx, "/mydir/subdir"),
            vec!["file_in_subdir".to_owned()]
        );
    }

    #[test]
    fn stating_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let proc = setup();

        let root_stat = proc.sc_stat("/").unwrap();
        assert_eq!(root_stat.size, 0);
        assert_eq!(root_stat.file_type, FileType::Directory);

        proc.sc_create("/myfile", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();
        assert_eq!(proc.sc_stat("/myfile").unwrap().size, 0);

        let fd = proc.sc_open("/myfile", OpenFlags::READ_ONLY, None).unwrap();
        proc.sc_write(fd, &[1, 2, 3]).unwrap();
        assert_eq!(proc.sc_stat("/myfile").unwrap().size, 3);
    }

    #[test]
    fn opening_and_closing_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();
        let fd = proc.sc_open("/myfile", OpenFlags::READ_ONLY, None).unwrap();
        proc.sc_close(fd).unwrap();
    }

    #[test]
    fn writing_seeking_and_reading() {
        let _lock = TEST_LOCK.lock().unwrap();
        let proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();
        let fd = proc.sc_open("/myfile", OpenFlags::READ_ONLY, None).unwrap();
        proc.sc_write(fd, &[0, 10, 20, 30]).unwrap();
        let buf = &mut [0, 0];
        proc.sc_seek(fd, SeekOffset::Set(1)).unwrap();
        let mut n = proc.sc_read(fd, buf).unwrap();
        assert_eq!(buf, &[10, 20]);
        assert_eq!(n, 2);
        n = proc.sc_read(fd, buf).unwrap();
        assert_eq!(buf, &[30, 20]);
        assert_eq!(n, 1);
        n = proc.sc_read(fd, buf).unwrap();
        assert_eq!(n, 0);
    }

    fn list_dir(ctx: &ProcessHandle, path: &str) -> Vec<String> {
        let fd = ctx.sc_open(path, OpenFlags::READ_ONLY, None).unwrap();
        let dents = ctx.sc_getdents(fd).unwrap();
        ctx.sc_close(fd).unwrap();
        dents.into_iter().map(|e| e.name).collect()
    }

    fn assert_dir_contains(ctx: &ProcessHandle, dir_path: &str, child_name: &str) {
        let listing = list_dir(ctx, dir_path);
        assert!(
            listing.contains(&child_name.to_owned()),
            "Unexpected dir contents: {:?}",
            listing
        );
    }

    #[test]
    fn changing_current_working_directory() {
        let _lock = TEST_LOCK.lock().unwrap();
        let proc = setup();
        proc.sc_create("/dir", FileType::Directory, FilePermissions::new(7, 7))
            .unwrap();
        proc.sc_create("dir/x", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();
        proc.sc_chdir("/dir").unwrap();
        assert_eq!(list_dir(&proc, "."), vec!["x"]);
        assert!(list_dir(&proc, "..").contains(&"dir".to_owned()));
    }

    #[test]
    fn rename_moving_file_between_directories() {
        let _lock = TEST_LOCK.lock().unwrap();
        let proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();
        assert!(list_dir(&proc, "/").contains(&"myfile".to_owned()));

        proc.sc_create("/dir", FileType::Directory, FilePermissions::new(7, 7))
            .unwrap();
        proc.sc_rename("/myfile", "/dir/moved").unwrap();

        assert!(!list_dir(&proc, "/").contains(&"myfile".to_owned()));
        assert_eq!(list_dir(&proc, "/dir"), vec!["moved"]);
    }

    #[test]
    fn rename_with_relative_paths() {
        let _lock = TEST_LOCK.lock().unwrap();
        let proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::new(7, 7))
            .unwrap();

        proc.sc_rename("myfile", "new_name").unwrap();

        assert_dir_contains(&proc, "/", "new_name");
    }
}
