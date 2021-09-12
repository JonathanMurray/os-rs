#![allow(dead_code)]
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::core::{Fd, FilePermissions, FileType, Ino, Pid};
use crate::procfs::ProcFilesystem;
use crate::regularfs::RegularFilesystem;

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

    fn get_mut(&mut self, pid: Pid) -> Option<&mut Process> {
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

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
    pub inode_number: Ino,
    pub filesystem: String,
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
    filesystem: FilesystemId,
    inode_number: Ino,
    fd: Fd,
    offset: usize,
}

#[derive(Debug)]
struct VirtualFilesystemSwitch {
    fs: RegularFilesystem,
    procfs: ProcFilesystem,
}

impl VirtualFilesystemSwitch {
    pub fn new() -> Self {
        let root_inode_id = InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: 0,
        };
        let root_inode = Inode {
            parent_id: root_inode_id, //root has self as parent
            id: root_inode_id,
            file_type: FileType::Directory,
            size: 0,
            permissions: FilePermissions::ReadOnly,
        };
        let mut fs = RegularFilesystem::new(root_inode);
        fs.add_child_to_directory(
            0,
            "proc".to_owned(),
            InodeIdentifier {
                filesystem_id: FilesystemId::Proc,
                number: 0,
            },
        )
        .expect("Add proc to root dir");
        let procfs = ProcFilesystem::new(root_inode_id);
        Self { fs, procfs }
    }

    pub fn create_file<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
        cwd: InodeIdentifier,
        filesystem_id: Option<FilesystemId>,
    ) -> Result<()> {
        let path = path.into();
        let parts: Vec<&str> = path.split('/').collect();
        let parent_inode = self.resolve_from_parts(&parts[..parts.len() - 1], cwd)?;
        let parent_id = parent_inode.id;

        if !parent_inode.is_dir() {
            return Err("Parent is not a directory".to_owned());
        }

        let name = parts[parts.len() - 1].to_owned();

        self._create_file(parent_id, file_type, permissions, filesystem_id, name)
    }

    fn _create_file(
        &mut self,
        parent_inode_id: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
        filesystem_id: Option<FilesystemId>,
        name: String,
    ) -> Result<()> {
        // file can be on different filesystem than its parent, for example /proc
        let filesystem_id = filesystem_id.unwrap_or(parent_inode_id.filesystem_id);

        if filesystem_id == FilesystemId::Main {
            let new_ino = self
                .fs
                .create_inode(file_type, permissions, parent_inode_id);
            self.fs.add_child_to_directory(
                parent_inode_id.number,
                name,
                InodeIdentifier {
                    filesystem_id,
                    number: new_ino,
                },
            )?;
        } else {
            return Err("Can't create inode on procfs".to_owned());
        };

        Ok(())
    }

    pub fn remove_file(&mut self, path: &str, cwd: InodeIdentifier) -> Result<()> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        let inode_id = inode.id;

        let inode = self.inode(inode_id)?;

        if inode.file_type == FileType::Directory {
            return Err("Cannot remove directory".to_owned());
        }
        let parent_id = inode.parent_id;

        match inode_id.filesystem_id {
            FilesystemId::Main => {
                self.fs.remove_inode(inode_id);
                self.fs
                    .remove_child_from_directory(parent_id.number, inode_id)
            }
            FilesystemId::Proc => Err("Can't remove file from procfs".to_owned()),
        }
    }

    pub fn rename_file<S: Into<String>>(
        &mut self,
        old_path: &str,
        new_path: S,
        cwd: InodeIdentifier,
    ) -> Result<()> {
        //TODO: handle replacing existing file
        let new_path = new_path.into();

        let old_parts: Vec<&str> = old_path.split('/').collect();
        let inode = self.resolve_from_parts(&old_parts, cwd)?;
        let inode_id = inode.id;
        let old_parent_id = inode.parent_id;

        if inode.file_type == FileType::Directory {
            return Err("Cannot move directory".to_owned());
        }

        let new_parts: Vec<&str> = new_path.split('/').collect();
        let new_base_name = new_parts[new_parts.len() - 1].to_owned();
        let new_parent_inode = self.resolve_from_parts(&new_parts[..new_parts.len() - 1], cwd)?;
        if new_parent_inode.id.filesystem_id != inode_id.filesystem_id {
            // To support this we'd need to create a new inode and copy the file contents
            return Err("Cannot move files between different filesystems".to_owned());
        }
        let new_parent_id = new_parent_inode.id;

        if new_parent_inode.file_type != FileType::Directory {
            return Err("New parent is not a directory".to_owned());
        }

        let old_parent_inode = self.inode(old_parent_id)?;
        if old_parent_inode.id.filesystem_id == FilesystemId::Proc {
            return Err("Cannot move file in procfs".to_owned());
        }
        assert!(old_parent_inode.is_dir());

        //TODO Maybe this should be: fs.rename(old_parent_id, inode_id, new_parent_id, new_name)
        self.fs.set_inode_parent(inode_id.number, new_parent_id)?;
        self.fs
            .remove_child_from_directory(old_parent_id.number, inode_id)?;
        self.fs
            .add_child_to_directory(new_parent_id.number, new_base_name, inode_id)
    }

    pub fn stat_file(&mut self, path: &str, cwd: InodeIdentifier) -> Result<FileStat> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;

        let permissions = inode.permissions;
        let inode_number = inode.id.number;
        let filesystem = format!("{:?}", inode.id.filesystem_id);

        Ok(FileStat {
            file_type: inode.file_type,
            size: inode.size,
            permissions,
            inode_number,
            filesystem,
        })
    }

    pub fn list_dir<S: Into<String>>(
        &mut self,
        path: S,
        cwd: InodeIdentifier,
    ) -> Result<Vec<String>> {
        let path = path.into();
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        if !inode.is_dir() {
            return Err("Not a directory".to_owned());
        }
        let inode_id = inode.id;

        match inode_id.filesystem_id {
            FilesystemId::Main => self.fs.list_directory(inode_id.number),
            FilesystemId::Proc => self.procfs.list_directory(inode_id.number),
        }
    }

    pub fn open_file(
        &mut self,
        path: &str,
        cwd: InodeIdentifier,
        fd: Fd,
    ) -> Result<(FilesystemId, Ino)> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        let fs = inode.id.filesystem_id;
        let ino = inode.id.number;

        match fs {
            FilesystemId::Main => {
                // Nothing needs to be done here
            }
            FilesystemId::Proc => {
                self.procfs.open_file(ino, fd)?;
            }
        }
        Ok((fs, ino))
    }

    pub fn close_file(&mut self, filesystem: FilesystemId, fd: Fd) -> Result<()> {
        match filesystem {
            FilesystemId::Main => {
                // Nothing needs to be done here
                Ok(())
            }
            FilesystemId::Proc => self.procfs.close_file(fd),
        }
    }

    pub fn read_file_at_offset(
        &mut self,
        fd: Fd,
        filesystem: FilesystemId,
        inode_number: Ino,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match filesystem {
            FilesystemId::Proc => self.procfs.read_file_at_offset(fd, buf, file_offset),
            FilesystemId::Main => self.fs.read_file_at_offset(inode_number, buf, file_offset),
        }
    }

    pub fn write_file_at_offset(
        &mut self,
        filesystem: FilesystemId,
        inode_number: Ino,
        buf: &[u8],
        file_offset: usize,
    ) -> Result<usize> {
        if filesystem == FilesystemId::Proc {
            Err("Can't write to procfs".to_owned())
        } else {
            self.fs.write_file_at_offset(inode_number, buf, file_offset)
        }
    }

    pub fn path_from_inode(&mut self, inode_id: InodeIdentifier) -> Result<String> {
        let mut parts_reverse = Vec::new();
        let mut inode = self.inode(inode_id)?;

        loop {
            if inode.parent_id == inode.id {
                // The root inode has itself as a parent
                break;
            }

            let parent_inode = self.inode(inode.parent_id)?;
            let name = match inode.parent_id.filesystem_id {
                FilesystemId::Main => self
                    .fs
                    .directory_child_name(inode.parent_id.number, inode.id)?,
                FilesystemId::Proc => todo!("procfs.directory_child_name()"),
            };
            parts_reverse.push(name);

            inode = parent_inode;
        }

        let mut path = String::new();
        for part in parts_reverse.into_iter().rev() {
            path.push('/');
            path.push_str(&part);
        }

        Ok(path)
    }

    fn resolve_from_parts(&mut self, mut parts: &[&str], cwd: InodeIdentifier) -> Result<Inode> {
        let mut inode = match parts.get(0) {
            Some(&"") => {
                // (empty string here means the path starts with '/', since we split on it)
                // We got an absolute path. Start from root.
                parts = &parts[1..];
                // TODO: better way for getting the root inode
                self.fs
                    .inode(0)
                    .expect("Must have root inode with number 0")
            }
            None => self.inode(cwd)?,    // creating a file in cwd
            Some(_) => self.inode(cwd)?, // creating further down
        };

        for part in parts {
            let inode_id = inode.id;

            let next_id = match *part {
                "." => {
                    continue;
                }
                "" => {
                    // Last part can be "" either if path is "/" or if path ends with a trailing slash.
                    // We choose to allow trailing slash to make things easy for now.
                    continue;
                }
                ".." => inode.parent_id,
                _ => match inode.id.filesystem_id {
                    FilesystemId::Main => self.fs.directory_child_id(inode_id.number, part)?,
                    FilesystemId::Proc => self.procfs.directory_child_id(inode_id.number, part)?,
                },
            };

            inode = self.inode(next_id)?;
        }

        let inode_id = inode.id;
        self.inode(inode_id)
    }

    fn resolve_directory(&mut self, path: &str, cwd: InodeIdentifier) -> Result<Inode> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        if inode.file_type != FileType::Directory {
            return Err(format!("Not a directory: {}", path));
        }
        Ok(inode)
    }

    fn inode(&self, inode_id: InodeIdentifier) -> Result<Inode> {
        match inode_id.filesystem_id {
            FilesystemId::Main => self.fs.inode(inode_id.number),
            FilesystemId::Proc => self.procfs.inode(inode_id.number),
        }
    }
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

    pub fn sc_close(&mut self, fd: Fd) -> Result<()> {
        let mut active_context = ActiveContext::new(self);
        let open_file = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("close({})", fd));
            proc.take_open_file(fd)?
        };

        active_context.sys.vfs.close_file(open_file.filesystem, fd)
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

    pub fn sc_read(&mut self, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        let mut active_context = ActiveContext::new(self);
        let (filesystem, inode_number, offset) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log.push(format!("read({}, buf)", fd));
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

    pub fn sc_write(&mut self, fd: Fd, buf: &[u8]) -> Result<()> {
        //TODO permissions

        let mut active_context = ActiveContext::new(self);
        let (filesystem, inode_number, offset) = {
            let mut processes = PROCESSES.lock().unwrap();
            let proc = processes.current();
            proc.log
                .push(format!("write({}, <{} bytes>)", fd, buf.len()));

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

    pub fn is_regular(&self) -> bool {
        self.file_type == FileType::Regular
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct InodeIdentifier {
    pub filesystem_id: FilesystemId,
    pub number: Ino,
}

#[derive(Debug)]
pub enum File {
    Regular(RegularFile),
    Dir(Directory),
}

impl File {
    pub fn new_regular() -> Self {
        File::Regular(RegularFile {
            content: Default::default(),
        })
    }

    pub fn new_dir() -> Self {
        File::Dir(Directory {
            children: Default::default(),
        })
    }

    pub fn new(file_type: FileType) -> Self {
        match file_type {
            FileType::Directory => File::new_dir(),
            FileType::Regular => File::new_regular(),
        }
    }
}

#[derive(Debug)]
pub struct RegularFile {
    pub content: Vec<u8>,
}

impl RegularFile {
    pub fn new() -> Self {
        Self {
            content: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct Directory {
    pub children: HashMap<String, InodeIdentifier>,
}

impl Directory {
    pub fn new() -> Self {
        Self {
            children: Default::default(),
        }
    }
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
            ctx.sc_list_dir("/mydir/subdir").unwrap(),
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

    #[test]
    fn changing_current_working_directory() {
        let _lock = TEST_LOCK.lock().unwrap();
        let mut proc = setup();
        proc.sc_create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_create("dir/x", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_chdir("/dir").unwrap();
        assert_eq!(proc.sc_list_dir(".").unwrap(), vec!["x"]);
        assert!(proc.sc_list_dir("..").unwrap().contains(&"dir".to_owned()));
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
            .contains(&"myfile".to_owned()));
        proc.sc_create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.sc_rename("/myfile", "/dir/moved").unwrap();
        assert!(!proc
            .sc_list_dir("/")
            .unwrap()
            .contains(&"myfile".to_owned()));
        assert_eq!(proc.sc_list_dir("/dir").unwrap(), vec!["moved"]);
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
            .contains(&"myfile".to_owned()));
        proc.sc_rename("myfile", "new_name").unwrap();
        assert!(proc
            .sc_list_dir("/")
            .unwrap()
            .contains(&"new_name".to_owned()));
    }
}
