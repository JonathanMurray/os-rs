use crate::util::{
    DirectoryEntry, Fd, FilePermissions, FileStat, FileType, FilesystemId, InodeIdentifier,
    OpenFileId, Pid,
};
use crate::vfs::VirtualFilesystemSwitch;
use once_cell::sync::Lazy;
use std::collections::{HashMap, LinkedList};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

type Result<T> = core::result::Result<T, String>;

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

pub struct GlobalProcessTable {
    next_pid: Pid,
    processes: HashMap<Pid, Process>,
    currently_running_pid: Option<Pid>,
}

impl GlobalProcessTable {
    fn add(&mut self, process_name: String, parent_pid: Pid, stdout: Option<OpenFileId>) -> Pid {
        let pid = self.next_pid;
        let process = Process::new(pid, parent_pid, process_name, stdout);
        self.next_pid = Pid(self.next_pid.0 + 1);
        self.processes.insert(pid, process);
        pid
    }

    fn remove(&mut self, pid: Pid) {
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
    Killed,
}

#[derive(Debug)]
pub struct Process {
    pub pid: Pid,
    pub parent_pid: Pid,
    pub name: String,
    pub fds: HashMap<Fd, OpenFileId>,
    next_fd: Fd,
    cwd: InodeIdentifier,
    pub log: Vec<String>,
    pub state: ProcessState,
    result: Option<ProcessResult>,
    incoming_kill_signals: LinkedList<()>,
}

impl Process {
    fn new(pid: Pid, parent_pid: Pid, name: String, stdout: Option<OpenFileId>) -> Self {
        //TODO don't rely on / having ino=0 everywhere
        let cwd = InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: 0,
        };

        let mut next_fd = 1;
        let mut fds = HashMap::new();
        if let Some(stdout) = stdout {
            fds.insert(next_fd, stdout);
            next_fd = 2;
        }

        Process {
            pid,
            parent_pid,
            name,
            fds,
            next_fd,
            cwd,
            log: vec![],
            state: ProcessState::Running,
            result: None,
            incoming_kill_signals: Default::default(),
        }
    }

    fn find_open_file(&mut self, fd: Fd) -> Result<OpenFileId> {
        self.fds
            .get(&fd)
            .copied()
            .ok_or_else(|| format!("No such fd: {}", fd))
    }

    fn take_open_file(&mut self, fd: Fd) -> Result<OpenFileId> {
        self.fds
            .remove(&fd)
            .ok_or_else(|| format!("No such fd: {}", fd))
    }

    fn take_fds(&mut self) -> HashMap<Fd, OpenFileId> {
        std::mem::take(&mut self.fds)
    }

    fn ensure_zombified(&mut self, result: ProcessResult) {
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
        self.ensure_zombified(result);
    }

    fn handle_kill_signal(&mut self) -> bool {
        if self.incoming_kill_signals.pop_back().is_some() {
            eprintln!(
                "{:?} got a kill signal and will now zombify itself",
                self.pid
            );
            self.zombify(ProcessResult::Killed);
            true
        } else {
            false
        }
    }

    fn kill_signal(&mut self) {
        self.incoming_kill_signals.push_front(());
    }
}

#[derive(Debug, Copy, Clone)]
pub struct OpenFile {
    fd: Fd,
    open_file_id: u32,
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
    pub fn new() -> Self {
        Self {
            vfs: VirtualFilesystemSwitch::new(),
        }
    }

    pub fn spawn_process(
        mut processes: MutexGuard<'_, GlobalProcessTable>,
        sys: Arc<Mutex<System>>,
        name: String,
        parent_pid: Pid,
        stdout: Option<OpenFileId>,
    ) -> ProcessHandle {
        let pid = processes.add(name, parent_pid, stdout);
        ProcessHandle {
            shared_sys: sys,
            pid,
        }
    }

    fn close_files(&mut self, open_files: impl Iterator<Item = OpenFileId>, pid: Pid) {
        for open_file_id in open_files {
            if let Err(e) = self.vfs.close_file(open_file_id, pid) {
                println!("WARN: Failed to close file: {}", e);
            }
        }
    }
}

fn close_zombies_fds(mut active_handle: ActiveProcessHandle, pid: Pid) {
    let mut processes = active_handle.process_table();
    let process = processes.process(pid).unwrap();
    let fds = process.take_fds();
    //Release lock before using VFS
    drop(processes);
    eprintln!("Closing zombie fds: {:?}", fds);
    active_handle.sys.close_files(fds.into_values(), pid);
}

#[derive(Debug)]
pub struct ProcessHandle {
    // Prefer to use sys from ActiveProcessHandle
    // to avoid potential deadlocks
    shared_sys: Arc<Mutex<System>>,
    pid: Pid,
}

impl ProcessHandle {
    pub fn process_name(&mut self) -> String {
        let active_handle = ActiveProcessHandle::new(self);
        let mut processes = active_handle.process_table();
        processes.current().name.clone()
    }

    pub fn handle_signals(mut self) -> Option<Self> {
        let pid = self.pid;
        {
            let active_handle = ActiveProcessHandle::new(&mut self);
            let mut processes = active_handle.process_table();
            let process = processes.process(pid).expect("This process must exist");
            let killed = process.handle_kill_signal();
            //Release process lock before using VFS
            drop(processes);
            if killed {
                eprintln!("{:?} was killed", pid);
                close_zombies_fds(active_handle, pid);
                return None;
            }
        };
        Some(self)
    }

    pub fn sc_getpid(&self) -> Pid {
        self.pid
    }

    pub fn sc_spawn<S: Into<String>>(&mut self, path: S, stdout: SpawnStdout) -> Result<Pid> {
        let path = path.into();
        let self_pid = self.pid;
        let child_sys = self.shared_sys.clone();
        let active_handle = ActiveProcessHandle::new(self);
        let mut processes = active_handle.process_table();
        let current_proc = processes.current();
        current_proc.log.push(format!("spawn({:?})", path));

        let child_stdout = match stdout {
            SpawnStdout::Inherit => current_proc.find_open_file(1).ok(),
            SpawnStdout::OpenFile(fd) => current_proc.find_open_file(fd).ok(),
        };
        eprintln!(
            "Spawning {} with stdout option: {:?}. Stdout became: {:?}",
            path, stdout, child_stdout
        );
        eprintln!("Current proc open files: {:?}", current_proc.fds);
        let child_handle =
            System::spawn_process(processes, child_sys, path, self_pid, child_stdout);
        let child_pid = child_handle.pid;

        let mut spawn_queue = GLOBAL_PROCESS_SPAWN_QUEUE.lock().unwrap();
        spawn_queue.push_front(child_handle);

        Ok(child_pid)
    }

    pub fn sc_exit(mut self, code: u32) {
        let self_pid = self.pid;
        let active_handle = ActiveProcessHandle::new(&mut self);

        let mut processes = active_handle.process_table();

        let proc = processes.current();
        proc.log.push(format!("exit({})", code));
        proc.zombify(ProcessResult::ExitCode(code));

        // Release process lock before using VFS
        drop(processes);

        close_zombies_fds(active_handle, self_pid);
    }

    pub fn sc_wait_pid(
        &mut self,
        target: WaitPidTarget,
        options: WaitPidOptions,
    ) -> Result<Option<(Pid, ProcessResult)>> {
        let self_pid = self.pid;
        {
            let active_context = ActiveProcessHandle::new(self);
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.state = ProcessState::Waiting;
            proc.log.push(format!("wait_pid({:?})", target));
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
                    let mut children = processes.children_mut(self_pid);
                    loop {
                        match children.next() {
                            Some(child) => {
                                if let Some(result) = child.result.take() {
                                    eprintln!("{:?} will reap {:?}", self_pid, child.pid);
                                    break Some((child.pid, result));
                                }
                            }
                            None => {
                                break None;
                            }
                        }
                    }
                }
            };
            if let Some((child_pid, child_result)) = child_and_result {
                processes.remove(child_pid);
                processes.current().state = ProcessState::Running;
                return Ok(Some((child_pid, child_result)));
            } else if options == WaitPidOptions::NoHang {
                processes.current().state = ProcessState::Running;
                return Ok(None);
            }
        }
    }

    pub fn sc_kill(&mut self, pid: Pid) -> Result<()> {
        //we only support SIGKILL for now.
        let active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let current_proc = processes.current();
        current_proc.log.push(format!("kill({:?})", pid));
        if active_context.pid == pid {
            return Err("Cannot kill self".to_owned());
        }
        let victim_proc = processes
            .process(pid)
            .ok_or_else(|| "No such process".to_owned())?;
        victim_proc.kill_signal();
        Ok(())
    }

    pub fn sc_create<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<()> {
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
            .create_file(path, file_type, permissions, cwd, None)
    }

    pub fn sc_open(&mut self, path: &str) -> Result<Fd> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("open({:?})", path));
        let (cwd, fd, pid) = (proc.cwd, proc.next_fd, proc.pid);
        // Release process lock before using VFS
        drop(processes);

        let open_file_id = active_context.sys.vfs.open_file(path, cwd, pid)?;

        eprintln!(
            "In sc_open: Opened fd {} with open_file_id: {:?}",
            fd, open_file_id
        );

        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.fds.insert(proc.next_fd, open_file_id);
        proc.next_fd += 1;
        Ok(fd)
    }

    pub fn sc_close(&mut self, fd: Fd) -> Result<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("close({})", fd));
        let pid = proc.pid;
        let open_file_id = proc.take_open_file(fd)?;
        eprintln!(
            "In sc_close: Closing fd {} with open_file_id: {:?}",
            fd, open_file_id
        );

        // Release process lock before using VFS
        drop(processes);
        active_context.sys.vfs.close_file(open_file_id, pid)
    }

    pub fn sc_stat(&mut self, path: &str) -> Result<FileStat> {
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

    pub fn sc_getdents(&mut self, fd: Fd) -> Result<Vec<DirectoryEntry>> {
        let mut active_context = ActiveProcessHandle::new(self);
        let open_file_id = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push(format!("getdents({})", fd));
            proc.find_open_file(fd)?
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.list_dir(open_file_id)
    }

    pub fn sc_read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
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

    pub fn sc_write(&mut self, fd: Fd, buf: &[u8]) -> Result<usize> {
        //TODO permissions

        let mut active_context = ActiveProcessHandle::new(self);
        let open_file_id = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log
                .push(format!("write({}, <{} bytes>)", fd, buf.len()));

            proc.find_open_file(fd)?
        };

        eprintln!(
            "In sc_write: found open file, fd {} as open_file_id {:?}",
            fd, open_file_id
        );

        // unlock process table before calling VFS
        let num_written = active_context.sys.vfs.write_file(open_file_id, buf)?;
        Ok(num_written)
    }

    pub fn sc_seek(&mut self, fd: Fd, offset: usize) -> Result<()> {
        let mut active_context = ActiveProcessHandle::new(self);
        let mut processes = active_context.process_table();
        let proc = processes.current();
        proc.log.push(format!("seek({}, {})", fd, offset));
        let open_file_id = proc.find_open_file(fd)?;

        // unlock process table before calling VFS
        drop(processes);
        active_context.sys.vfs.seek(open_file_id, offset)
    }

    pub fn sc_chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
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
        let mut proc = processes.current();
        proc.cwd = cwd;
        Ok(())
    }

    pub fn sc_get_current_dir_name(&mut self) -> Result<String> {
        let mut active_context = ActiveProcessHandle::new(self);
        let cwd = {
            let mut processes = active_context.process_table();
            let proc = processes.current();
            proc.log.push("get_current_dir_name()".to_owned());
            proc.cwd
        };

        // unlock process table before calling VFS
        active_context.sys.vfs.path_from_inode(cwd)
    }

    pub fn sc_unlink(&mut self, path: &str) -> Result<()> {
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

    pub fn sc_rename<S: Into<String>>(&mut self, old_path: &str, new_path: S) -> Result<()> {
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
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let pid = self.pid;
        let mut sys = self.shared_sys.lock().unwrap();

        eprintln!("{:?} getting processes in ProcessHandle::drop", pid);

        // LOCKING: We have locked System above
        let mut processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
        eprintln!("{:?} got processes in ProcessHandle::drop", pid);

        if let Some(p) = processes.process(pid) {
            p.ensure_zombified(ProcessResult::ExitCode(0));
            let fds = p.take_fds();
            eprintln!("Dropping process {:?}. Will close fds: {:?}", pid, fds);
            // Release process lock before using VFS
            drop(processes);
            sys.close_files(fds.into_values(), pid);
        } else {
            eprintln!("Process has already been reaped");
        }
    }
}

#[derive(Debug)]
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
pub enum SpawnStdout {
    Inherit,
    OpenFile(Fd),
}

struct ActiveProcessHandle<'a> {
    pid: Pid,
    sys: MutexGuard<'a, System>,
}

impl<'a> ActiveProcessHandle<'a> {
    fn new(handle: &'a mut ProcessHandle) -> Self {
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

    // Can't run tests in parallel, as they all spawn processes from a new
    // System. When running the OS normally, there is exactly one System.
    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn setup() -> ProcessHandle {
        let sys = System::new();
        System::spawn_process(
            GLOBAL_PROCESS_TABLE.lock().unwrap(),
            Arc::new(Mutex::new(sys)),
            "test".to_owned(),
            Pid(0),
            None,
        )
    }

    #[test]
    fn creating_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut ctx = setup();
        ctx.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
    }

    #[test]
    fn creating_files_and_listing_them() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut ctx = setup();
        ctx.sc_create("/mydir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        ctx.sc_create(
            "/mydir/subdir",
            FileType::Directory,
            FilePermissions::ReadWrite,
        )
        .unwrap();
        ctx.sc_create(
            "/mydir/file_in_dir",
            FileType::Regular,
            FilePermissions::ReadWrite,
        )
        .unwrap();
        ctx.sc_create(
            "/mydir/subdir/file_in_subdir",
            FileType::Regular,
            FilePermissions::ReadWrite,
        )
        .unwrap();

        assert_eq!(
            list_dir(&mut ctx, "/mydir/subdir"),
            vec!["file_in_subdir".to_owned()]
        );
    }

    #[test]
    fn stating_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();

        let root_stat = proc.sc_stat("/").unwrap();
        assert_eq!(root_stat.size, 0);
        assert_eq!(root_stat.file_type, FileType::Directory);

        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(proc.sc_stat("/myfile").unwrap().size, 0);

        let fd = proc.sc_open("/myfile").unwrap();
        proc.sc_write(fd, &[1, 2, 3]).unwrap();
        assert_eq!(proc.sc_stat("/myfile").unwrap().size, 3);
    }

    #[test]
    fn opening_and_closing_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        let fd = proc.sc_open("/myfile").unwrap();
        proc.sc_close(fd).unwrap();
    }

    #[test]
    fn writing_seeking_and_reading() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        let fd = proc.sc_open("/myfile").unwrap();
        proc.sc_write(fd, &[0, 10, 20, 30]).unwrap();
        let buf = &mut [0, 0];
        proc.sc_seek(fd, 1).unwrap();
        let mut n = proc.sc_read(fd, buf).unwrap();
        assert_eq!(buf, &[10, 20]);
        assert_eq!(n, 2);
        n = proc.sc_read(fd, buf).unwrap();
        assert_eq!(buf, &[30, 20]);
        assert_eq!(n, 1);
        n = proc.sc_read(fd, buf).unwrap();
        assert_eq!(n, 0);
    }

    fn list_dir(ctx: &mut ProcessHandle, path: &str) -> Vec<String> {
        let fd = ctx.sc_open(path).unwrap();
        let dents = ctx.sc_getdents(fd).unwrap();
        ctx.sc_close(fd).unwrap();
        dents.into_iter().map(|e| e.name).collect()
    }

    fn assert_dir_contains(ctx: &mut ProcessHandle, dir_path: &str, child_name: &str) {
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
        let mut proc = setup();
        proc.sc_create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_create("dir/x", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_chdir("/dir").unwrap();
        assert_eq!(list_dir(&mut proc, "."), vec!["x"]);
        assert!(list_dir(&mut proc, "..").contains(&"dir".to_owned()));
    }

    #[test]
    fn rename_moving_file_between_directories() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert!(list_dir(&mut proc, "/").contains(&"myfile".to_owned()));

        proc.sc_create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_rename("/myfile", "/dir/moved").unwrap();

        assert!(!list_dir(&mut proc, "/").contains(&"myfile".to_owned()));
        assert_eq!(list_dir(&mut proc, "/dir"), vec!["moved"]);
    }

    #[test]
    fn rename_with_relative_paths() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();

        proc.sc_rename("myfile", "new_name").unwrap();

        assert_dir_contains(&mut proc, "/", "new_name");
    }
}
