use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::core::{Fd, FilePermissions, FileType, Ino, Pid};
use crate::vfs::VirtualFilesystemSwitch;

type Result<T> = core::result::Result<T, String>;

static PROCESSES: Lazy<Mutex<GlobalProcessList>> = Lazy::new(|| {
    Mutex::new(GlobalProcessList {
        next_pid: 0,
        processes: Default::default(),
        currently_running_pid: None,
    })
});

pub struct GlobalProcessList {
    next_pid: Pid,
    pub processes: HashMap<Pid, Process>,
    pub currently_running_pid: Option<Pid>,
}

pub fn processes() -> MutexGuard<'static, GlobalProcessList> {
    PROCESSES.lock().unwrap()
}

impl GlobalProcessList {
    fn add(&mut self, process_name: String) -> Pid {
        let pid = self.next_pid;
        self.next_pid += 1;
        let proc = Process {
            pid,
            name: process_name,
            open_files: Default::default(),
            next_fd: 0,
            cwd: InodeIdentifier {
                filesystem_id: FilesystemId::Main,
                number: 0,
            }, //TODO don't rely on / having ino=0 everywhere
            log: vec![],
        };

        self.processes.insert(pid, proc);
        pid
    }

    pub fn current(&mut self) -> &mut Process {
        let pid = self.currently_running_pid.unwrap();
        self.processes.get_mut(&pid).unwrap()
    }
}

#[derive(Debug)]
pub struct System {
    vfs: VirtualFilesystemSwitch,
}

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
    pub inode_id: InodeIdentifier,
}

#[derive(PartialEq, Debug)]
pub struct DirectoryEntry {
    pub inode_number: Ino,
    pub name: String,
    pub file_type: FileType,
}

#[derive(Debug)]
pub struct Process {
    pub pid: Pid,
    pub name: String,
    pub open_files: Vec<OpenFile>,
    next_fd: Fd,
    cwd: InodeIdentifier,
    pub log: Vec<String>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FilesystemId {
    Main,
    Proc,
}

#[derive(Debug, Copy, Clone)]
pub struct OpenFile {
    inode_id: InodeIdentifier,
    fd: Fd,
    offset: usize,
}

impl System {
    pub fn new() -> Self {
        Self {
            vfs: VirtualFilesystemSwitch::new(),
        }
    }

    pub fn spawn_process(sys: Arc<Mutex<System>>, process_name: String) -> Context {
        let pid = PROCESSES.lock().unwrap().add(process_name);
        Context { sys, pid }
    }
}

struct ActiveContext<'a> {
    sys: MutexGuard<'a, System>,
}

impl<'a> ActiveContext<'a> {
    fn new(syscalls: &'a mut Context) -> Self {
        let sys = syscalls.sys.lock().unwrap();
        let mut processes = PROCESSES.lock().unwrap();
        assert!(
            processes.currently_running_pid.is_none(),
            "Another process is already active"
        );
        processes.currently_running_pid = Some(syscalls.pid);

        ActiveContext { sys }
    }
}

impl Drop for ActiveContext<'_> {
    fn drop(&mut self) {
        let mut processes = PROCESSES.lock().unwrap();
        assert!(
            processes.currently_running_pid.is_some(),
            "This process is not marked as active"
        );
        processes.currently_running_pid = None;
    }
}

pub struct Context {
    sys: Arc<Mutex<System>>,
    pid: Pid,
}

impl Context {
    pub fn sc_create<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let path = path.into();
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("create({:?})", path));
            proc.cwd
        };

        active_context
            .sys
            .vfs
            .create_file(path, file_type, permissions, cwd, None)
    }

    pub fn sc_open(&mut self, path: &str) -> Result<Fd> {
        let mut active_context = ActiveContext::new(self);
        let (cwd, fd) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("open({:?})", path));
            (proc.cwd, proc.next_fd)
        };

        let inode_id = active_context.sys.vfs.open_file(path, cwd, fd)?;

        let mut processes = PROCESSES.lock().unwrap();
        let proc = processes.current();
        proc.next_fd += 1;
        proc.open_files.push(OpenFile {
            inode_id,
            fd,
            offset: 0,
        });
        Ok(fd)
    }

    pub fn sc_close(&mut self, fd: Fd) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let open_file = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("close({})", fd));
            proc.take_open_file(fd)?
        };

        active_context
            .sys
            .vfs
            .close_file(open_file.inode_id.filesystem_id, fd)
    }

    pub fn sc_stat(&mut self, path: &str) -> Result<FileStat> {
        let mut active_context = ActiveContext::new(self);
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("stat({:?})", path));
            proc.cwd
        };

        active_context.sys.vfs.stat_file(path, cwd)
    }

    pub fn sc_getdents(&mut self, fd: Fd) -> Result<Vec<DirectoryEntry>> {
        let mut active_context = ActiveContext::new(self);
        let inode_id = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("getdents({})", fd));
            let of = proc.find_open_file_mut(fd)?;
            of.inode_id
        };

        active_context.sys.vfs.list_dir(inode_id)
    }

    pub fn sc_read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        let mut active_context = ActiveContext::new(self);
        let (inode_id, offset) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("read({}, buf)", fd));
            let of = proc.find_open_file_mut(fd)?;
            (of.inode_id, of.offset)
        };

        let result = active_context
            .sys
            .vfs
            .read_file_at_offset(fd, inode_id, buf, offset);

        if let Ok(num_read) = result {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            let mut of = proc.find_open_file_mut(fd)?;

            of.offset += num_read;
        }
        result
    }

    pub fn sc_write(&mut self, fd: Fd, buf: &[u8]) -> Result<()> {
        //TODO permissions

        let mut active_context = ActiveContext::new(self);
        let (inode_id, offset) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log
                .push(format!("write({}, <{} bytes>)", fd, buf.len()));

            let of = proc.find_open_file_mut(fd)?;
            (of.inode_id, of.offset)
        };

        let num_written = active_context
            .sys
            .vfs
            .write_file_at_offset(inode_id, buf, offset)?;

        let mut processes = PROCESSES.lock().unwrap();
        let proc = processes.current();
        let mut open_file = proc.find_open_file_mut(fd)?;
        open_file.offset += num_written;
        Ok(())
    }

    pub fn sc_seek(&mut self, fd: Fd, offset: usize) -> Result<()> {
        let _active_context = ActiveContext::new(self);
        let mut processes = PROCESSES.lock().unwrap();
        let proc = processes.current();
        proc.log.push(format!("seek({}, {})", fd, offset));
        let mut of = proc.find_open_file_mut(fd)?;
        of.offset = offset;
        Ok(())
    }

    pub fn sc_chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let path = path.into();
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("chdir({:?})", path));
            proc.cwd
        };

        let new_cwd_inode = active_context.sys.vfs.resolve_directory(&path, cwd)?;

        let cwd = new_cwd_inode.id;

        let mut processes = PROCESSES.lock().unwrap();
        let mut proc = processes.current();
        proc.cwd = cwd;
        Ok(())
    }

    pub fn sc_get_current_dir_name(&mut self) -> Result<String> {
        let mut active_context = ActiveContext::new(self);
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push("get_current_dir_name()".to_owned());
            proc.cwd
        };

        active_context.sys.vfs.path_from_inode(cwd)
    }

    pub fn sc_remove(&mut self, path: &str) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("remove({:?})", path));
            proc.cwd
        };

        active_context.sys.vfs.remove_file(path, cwd)
    }

    pub fn sc_rename<S: Into<String>>(&mut self, old_path: &str, new_path: S) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let new_path = new_path.into();
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log
                .push(format!("rename({:?}, {:?})", old_path, new_path));
            proc.cwd
        };

        active_context.sys.vfs.rename_file(old_path, new_path, cwd)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let mut processes = PROCESSES.lock().unwrap();
        processes.processes.remove(&self.pid);
    }
}

impl Process {
    fn find_open_file_mut(&mut self, fd: Fd) -> Result<&mut OpenFile> {
        self.open_files
            .iter_mut()
            .find(|f| f.fd == fd)
            .ok_or_else(|| format!("No such fd: {}", fd))
    }

    fn take_open_file(&mut self, fd: Fd) -> Result<OpenFile> {
        match self.open_files.iter().position(|f| f.fd == fd) {
            Some(index) => Ok(self.open_files.swap_remove(index)),
            None => Err(format!("No such fd: {}", fd)),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Inode {
    pub parent_id: InodeIdentifier,
    pub id: InodeIdentifier,
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct InodeIdentifier {
    pub filesystem_id: FilesystemId,
    pub number: Ino,
}

#[cfg(test)]
mod tests {

    use super::*;

    // Can't run tests in parallel, as they all spawn processes from a new
    // System. When running the OS normally, there is exactly one System.
    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn setup() -> Context {
        let sys = System::new();
        System::spawn_process(Arc::new(Mutex::new(sys)), "test".to_owned())
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

    fn list_dir(ctx: &mut Context, path: &str) -> Vec<String> {
        let fd = ctx.sc_open(path).unwrap();
        let dents = ctx.sc_getdents(fd).unwrap();
        ctx.sc_close(fd).unwrap();
        dents.into_iter().map(|e| e.name).collect()
    }

    fn assert_dir_contains(ctx: &mut Context, dir_path: &str, child_name: &str) {
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
