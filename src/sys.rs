#![allow(dead_code)]
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::core::{FilePermissions, FileType, Path};
use crate::procfs::ProcFilesystem;

type Result<T> = core::result::Result<T, String>;

//TODO: doc says Lazy is "thread-safe". Do we not need the Mutex?
static PROCESSES: Lazy<Mutex<GlobalProcessList>> = Lazy::new(|| {
    Mutex::new(GlobalProcessList {
        next_pid: 0,
        processes: Default::default(),
        currently_running_pid: None,
    })
});

pub struct GlobalProcessList {
    next_pid: u32,
    pub processes: HashMap<u32, Process>,
    pub currently_running_pid: Option<u32>,
}

pub fn processes() -> MutexGuard<'static, GlobalProcessList> {
    PROCESSES.lock().unwrap()
}

impl GlobalProcessList {
    fn add(&mut self, process_name: String) -> u32 {
        let pid = self.next_pid;
        self.next_pid += 1;
        let proc = Process {
            pid,
            name: process_name,
            open_files: Default::default(),
            next_fd: 0,
            cwd: 0,
            log: vec![],
        };

        self.processes.insert(pid, proc);
        pid
    }

    fn get_mut(&mut self, pid: u32) -> Option<&mut Process> {
        self.processes.get_mut(&pid)
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

#[derive(Debug)]
struct VirtualFilesystemSwitch {
    inodes: Vec<Inode>,
    next_inode_number: u32,
    procfs: ProcFilesystem,
}

#[derive(Debug)]
struct Inode {
    inode_number: u32,
    path: Path,
    file: File,
    permissions: FilePermissions,
}

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
    pub inode_number: u32,
    pub filesystem: String,
}

#[derive(Debug)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub open_files: Vec<OpenFile>,
    next_fd: u32,
    cwd: u32,
    pub log: Vec<String>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum FilesystemId {
    Main,
    Proc,
}

#[derive(Debug, Copy, Clone)]
pub struct OpenFile {
    filesystem: FilesystemId,
    inode_number: u32,
    fd: u32,
    offset: usize,
}

impl VirtualFilesystemSwitch {
    pub fn new(procfs: ProcFilesystem) -> Self {
        let root_dir = Inode {
            inode_number: 0,
            path: Path::new("/".to_owned()),
            file: File::new_dir(),
            permissions: FilePermissions::ReadOnly,
        };
        Self {
            inodes: vec![root_dir],
            next_inode_number: 1,
            procfs,
        }
    }

    pub fn create_file<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
        cwd: u32,
    ) -> Result<()> {
        let path = path.into();
        let path = self._resolve_path(path, cwd);
        let parent = path.parent();
        if parent.starts_with("/proc") {
            return Err("Cannot create file in procfs".to_owned());
        }
        let inode_number = self.next_inode_number;
        self.next_inode_number += 1;
        self.parent_dir(&path)?.children.push(inode_number);
        let file = File::new(file_type);
        self.inodes.push(Inode {
            inode_number,
            path,
            file,
            permissions,
        });
        Ok(())
    }

    pub fn rename_file<S: Into<String>>(
        &mut self,
        old_path: &str,
        new_path: S,
        cwd: u32,
    ) -> Result<()> {
        //TODO: handle replacing existing file
        let new_path = new_path.into();
        let old_path = self._resolve_path(old_path, cwd);
        let new_path = self._resolve_path(new_path, cwd);
        if new_path.starts_with("/proc") {
            return Err("Cannot create file in procfs".to_owned());
        }

        let file = self.inode_mut_from_path(&old_path)?;
        if file.permissions == FilePermissions::ReadOnly {
            return Err("Not permitted to rename file".to_owned());
        }

        file.path = new_path.clone();
        let inode_number = file.inode_number;

        let old_parent = self.parent_dir(&old_path)?;
        old_parent.children.retain(|child| *child != inode_number);
        let new_parent = self.parent_dir(&new_path)?;
        new_parent.children.push(inode_number);
        Ok(())
    }

    pub fn remove_file(&mut self, path: &str, cwd: u32) -> Result<()> {
        //TODO handle removing directories
        let path = self._resolve_path(path, cwd);
        if path.starts_with("/proc") {
            return Err("Cannot remove file in procfs".to_owned());
        }

        let file_entry = self.inode_mut_from_path(&path)?;
        if file_entry.permissions == FilePermissions::ReadOnly {
            return Err("Not permitted to remove file".to_owned());
        }
        let inode_number = file_entry.inode_number;
        self.inodes.retain(|f| f.path != path);
        let parent = self.parent_dir(&path)?;
        parent.children.retain(|child| *child != inode_number);
        Ok(())
    }

    pub fn open_file(&mut self, path: &str, cwd: u32, fd: u32) -> Result<(FilesystemId, u32)> {
        let path = self._resolve_path(path, cwd);
        if path.starts_with("/proc") {
            let inode_number = self.procfs.open_file(&path, fd)?;
            Ok((FilesystemId::Proc, inode_number))
        } else {
            let inode_number = self.inode_mut_from_path(&path)?.inode_number;
            Ok((FilesystemId::Main, inode_number))
        }
    }

    pub fn close_file(&mut self, filesystem: FilesystemId, fd: u32) -> Result<()> {
        match filesystem {
            FilesystemId::Proc => self.procfs.close_file(fd),
            FilesystemId::Main => {
                // Nothing needs to be done here
                Ok(())
            }
        }
    }

    pub fn write_file_at_offset(
        &mut self,
        filesystem: FilesystemId,
        inode_number: u32,
        buf: &[u8],
        mut file_offset: usize,
    ) -> Result<usize> {
        if filesystem == FilesystemId::Proc {
            return Err("Can't write to procfs".to_owned());
        }
        //TODO permissions
        let f = &mut self
            .inodes
            .iter_mut()
            .find(|f| f.inode_number == inode_number)
            .ok_or_else(|| "Cannot write. No such file".to_owned())?
            .file;
        let mut num_written = 0;
        if let File::Regular(ref mut f) = f {
            for &b in buf {
                if file_offset < f.content.len() {
                    f.content[file_offset] = b;
                } else {
                    f.content.push(b);
                }
                file_offset += 1;
                num_written += 1;
            }
        }

        Ok(num_written)
    }

    pub fn read_file_at_offset(
        &mut self,
        fd: u32,
        filesystem: FilesystemId,
        inode_number: u32,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        if filesystem == FilesystemId::Proc {
            return self
                .procfs
                .read_file_at_offset(fd, inode_number, buf, file_offset);
        }

        let file = &self
            .inodes
            .iter()
            .find(|f| f.inode_number == inode_number)
            .ok_or_else(|| "fd pointing to non-existent file".to_owned())?
            .file;

        match file {
            File::Regular(regular_file) => {
                let mut cursor = Cursor::new(&regular_file.content);
                cursor.set_position(file_offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(num_read)
            }
            File::Dir(_) => Err("Can't read directory".to_owned()),
        }
    }

    pub fn stat_file(&mut self, path: &str, cwd: u32) -> Result<FileStat> {
        let path = self._resolve_path(path, cwd);
        if path.starts_with("/proc") {
            return self.procfs.stat_file(&path);
        }
        let file_entry = self.inode_mut_from_path(&path)?;
        let permissions = file_entry.permissions;
        let inode_number = file_entry.inode_number;
        let filesystem = "mainfs".to_owned();

        match &file_entry.file {
            File::Regular(regular_file) => Ok(FileStat {
                file_type: FileType::Regular,
                size: regular_file.content.len(),
                permissions,
                inode_number,
                filesystem,
            }),
            File::Dir(_) => Ok(FileStat {
                file_type: FileType::Directory,
                size: 0,
                permissions,
                inode_number,
                filesystem,
            }),
        }
    }

    pub fn list_dir<S: Into<String>>(&mut self, path: S, cwd: u32) -> Result<Vec<String>> {
        let path = self._resolve_path(path.into(), cwd);
        if path.starts_with("/proc") {
            return self.procfs.list_dir(&path);
        }
        let f = &self
            .inodes
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| format!("Directory not found: '{:?}'", path))?
            .file;
        let mut child_names = Vec::new();
        if let File::Dir(dir) = f {
            for &id in &dir.children {
                let name = self
                    .inode_from_number(id)
                    .expect("child with valid inode")
                    .path
                    .clone();
                child_names.push(name.into());
            }
            Ok(child_names)
        } else {
            Err(format!("File is not a directory: {:?}", path))
        }
    }

    pub fn resolve_dir<S: Into<String>>(&mut self, path: S, cwd: u32) -> Result<u32> {
        //TODO: handle subdirs of /proc
        let path = path.into();
        let path = self._resolve_path(path, cwd);
        let inode = &self
            .inodes
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| format!("Directory not found: '{:?}'", path))?;
        if let File::Dir(_) = &inode.file {
            Ok(inode.inode_number)
        } else {
            Err(format!("Not a directory: {:?}", path))
        }
    }

    pub fn file_name(&mut self, inode_number: u32) -> Path {
        //TODO include filesystem identifier
        let inode = self
            .inode_from_number(inode_number)
            .expect("cwd valid inode");
        inode.path.clone()
    }

    fn _resolve_path<S: Into<String>>(&self, path: S, cwd_inode_number: u32) -> Path {
        let path = path.into();
        if path.starts_with('/') {
            // it's an absolute path
            Path::new(path)
        } else {
            let cwd_inode = self
                .inode_from_number(cwd_inode_number)
                .expect("cwd valid inode");
            cwd_inode.path.clone().resolve(&path)
        }
    }

    fn parent_dir(&mut self, path: &Path) -> Result<&mut Directory> {
        let parent_path = path.parent();
        let parent = &mut self.inode_mut_from_path(&parent_path)?.file;
        match parent {
            File::Dir(ref mut dir) => Ok(dir),
            _ => panic!("Parent {:?} is not a directory", parent_path),
        }
    }

    fn inode_mut_from_path(&mut self, path: &Path) -> Result<&mut Inode> {
        self.inodes
            .iter_mut()
            .find(|f| &f.path == path)
            .ok_or_else(|| format!("No inode with path: '{:?}'", path))
    }

    fn inode_from_number(&self, inode_number: u32) -> Result<&Inode> {
        self.inodes
            .iter()
            .find(|f| f.inode_number == inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }
}

impl System {
    pub fn new() -> Self {
        let procfs = ProcFilesystem::new();
        let mut vfs = VirtualFilesystemSwitch::new(procfs);
        vfs.create_file("/syslog", FileType::Regular, FilePermissions::ReadOnly, 0)
            .unwrap();
        vfs.create_file("/proc", FileType::Directory, FilePermissions::ReadOnly, 0)
            .unwrap();
        Self { vfs }
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
    pid: u32,
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
            .create_file(path, file_type, permissions, cwd)
    }

    pub fn sc_open(&mut self, path: &str) -> Result<u32> {
        let mut active_context = ActiveContext::new(self);
        let (cwd, fd) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("open({:?})", path));
            (proc.cwd, proc.next_fd)
        };

        let (filesystem, inode_number) = active_context.sys.vfs.open_file(path, cwd, fd)?;

        let mut processes = PROCESSES.lock().unwrap();
        let proc = processes.current();
        proc.next_fd += 1;
        proc.open_files.push(OpenFile {
            filesystem,
            inode_number,
            fd,
            offset: 0,
        });
        Ok(fd)
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

    pub fn sc_list_dir<S: Into<String>>(&mut self, path: S) -> Result<Vec<String>> {
        let mut active_context = ActiveContext::new(self);
        let path = path.into();
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("list_dir({:?})", path));
            proc.cwd
        };

        active_context.sys.vfs.list_dir(path, cwd)
    }

    pub fn sc_get_current_dir_name(&mut self) -> Path {
        let mut active_context = ActiveContext::new(self);
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push("get_current_dir_name()".to_owned());
            proc.cwd
        };

        active_context.sys.vfs.file_name(cwd)
    }

    pub fn sc_write(&mut self, fd: u32, buf: &[u8]) -> Result<()> {
        //TODO permissions

        let mut active_context = ActiveContext::new(self);
        let (filesystem, inode_number, offset) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log
                .push(format!("write({}, <{} bytes>", fd, buf.len()));

            let of = proc.find_open_file_mut(fd)?;
            (of.filesystem, of.inode_number, of.offset)
        };

        let num_written =
            active_context
                .sys
                .vfs
                .write_file_at_offset(filesystem, inode_number, buf, offset)?;

        let mut processes = PROCESSES.lock().unwrap();
        let proc = processes.current();
        let mut open_file = proc.find_open_file_mut(fd)?;
        open_file.offset += num_written;
        Ok(())
    }

    pub fn sc_seek(&mut self, fd: u32, offset: usize) -> Result<()> {
        let _active_context = ActiveContext::new(self);
        let mut processes = PROCESSES.lock().unwrap();
        let proc = processes.current();
        proc.log.push(format!("seek({}, {}", fd, offset));
        let mut of = proc.find_open_file_mut(fd)?;
        of.offset = offset;
        Ok(())
    }

    pub fn sc_read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize> {
        let mut active_context = ActiveContext::new(self);
        let (filesystem, inode_number, offset) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("read({}, buf", fd));
            let of = proc.find_open_file_mut(fd)?;
            (of.filesystem, of.inode_number, of.offset)
        };

        let result =
            active_context
                .sys
                .vfs
                .read_file_at_offset(fd, filesystem, inode_number, buf, offset);

        if let Ok(num_read) = result {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            let mut of = proc.find_open_file_mut(fd)?;

            of.offset += num_read;
        }
        result
    }

    pub fn sc_close(&mut self, fd: u32) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let open_file = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("close({})", fd));
            proc.take_open_file(fd)?
        };

        active_context.sys.vfs.close_file(open_file.filesystem, fd)
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

    pub fn sc_chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let path = path.into();
        let cwd = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("chdir({:?})", path));
            proc.cwd
        };

        let cwd = active_context.sys.vfs.resolve_dir(path, cwd)?;

        let mut processes = PROCESSES.lock().unwrap();
        let mut proc = processes.current();
        proc.cwd = cwd;
        Ok(())
    }
}

impl Process {
    fn find_open_file_mut(&mut self, fd: u32) -> Result<&mut OpenFile> {
        self.open_files
            .iter_mut()
            .find(|f| f.fd == fd)
            .ok_or_else(|| format!("No such fd: {}", fd))
    }

    fn take_open_file(&mut self, fd: u32) -> Result<OpenFile> {
        match self.open_files.iter().position(|f| f.fd == fd) {
            Some(index) => Ok(self.open_files.swap_remove(index)),
            None => Err(format!("No such fd: {}", fd)),
        }
    }
}

#[derive(Debug)]
enum File {
    Regular(RegularFile),
    Dir(Directory),
}

impl File {
    fn new_regular() -> Self {
        File::Regular(RegularFile {
            content: Default::default(),
        })
    }

    fn new_dir() -> Self {
        File::Dir(Directory {
            children: Default::default(),
        })
    }

    fn new(file_type: FileType) -> Self {
        match file_type {
            FileType::Directory => File::new_dir(),
            FileType::Regular => File::new_regular(),
        }
    }
}

#[derive(Debug)]
struct RegularFile {
    content: Vec<u8>,
}

#[derive(Debug)]
struct Directory {
    children: Vec<u32>,
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
    fn create() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
    }

    #[test]
    fn rename_moving_file_between_directories() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert!(proc
            .sc_list_dir("/")
            .unwrap()
            .contains(&"/myfile".to_owned()));
        proc.sc_create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_rename("/myfile", "/dir/moved").unwrap();
        assert!(!proc
            .sc_list_dir("/")
            .unwrap()
            .contains(&"/myfile".to_owned()));
        assert_eq!(proc.sc_list_dir("/dir").unwrap(), vec!["/dir/moved"]);
    }

    #[test]
    fn rename_with_relative_paths() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert!(proc
            .sc_list_dir("/")
            .unwrap()
            .contains(&"/myfile".to_owned()));
        proc.sc_rename("myfile", "new_name").unwrap();
        assert!(proc
            .sc_list_dir("/")
            .unwrap()
            .contains(&"/new_name".to_owned()));
    }

    #[test]
    fn write_seek_read() {
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

    #[test]
    fn stat_file() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(proc.sc_stat("/myfile").unwrap().size, 0);
        let fd = proc.sc_open("/myfile").unwrap();
        proc.sc_write(fd, &[1, 2, 3]).unwrap();
        assert_eq!(proc.sc_stat("/myfile").unwrap().size, 3);
    }

    #[test]
    fn chdir() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_create("dir/x", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_chdir("/dir").unwrap();
        assert_eq!(proc.sc_list_dir(".").unwrap(), vec!["/dir/x"]);
    }
}
