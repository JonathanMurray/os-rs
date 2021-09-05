use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

use crate::procfs::ProcFilesystem;

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct System {
    vfs: VirtualFilesystemSwitch,
    next_pid: u32,
    // shared between system and procfs.
    processes: Arc<Mutex<Processes>>,
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

#[derive(Debug, Clone, PartialEq)]
pub struct Path(String);

// A canonical absolute path
impl Path {
    pub fn resolve(mut self, relative_path: &str) -> Self {
        if relative_path == "." {
            return self;
        }
        if !self.0.ends_with('/') {
            self.0.push('/');
        }
        self.0.push_str(relative_path);
        self
    }

    pub fn parent(&self) -> Self {
        let (mut parent_path, _) = self
            .0
            .rsplit_once('/')
            .expect("canonical path must have parent");
        if parent_path.is_empty() {
            parent_path = "/";
        }
        Path(parent_path.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(PartialEq, Debug)]
pub enum FileType {
    Regular,
    Directory,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FilePermissions {
    ReadWrite,
    ReadOnly,
}

// Processes can be accessed from different threads.
pub type Processes = HashMap<u32, Arc<Mutex<_Process>>>;

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
    pub inode_number: u32,
    pub filesystem: String,
}

#[derive(Debug)]
pub struct Process(Arc<Mutex<_Process>>);

#[derive(Debug)]
pub struct _Process {
    pub pid: u32,
    pub name: String,
    // A reference to the underlying system, shared between threads
    sys: Option<Arc<Mutex<System>>>,
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
            path: Path("/".to_owned()),
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
        //sys.log(&format!("create({:?}, {:?})", path, file_type));
        let path = self._resolve_path(path, cwd);
        let parent = path.parent();
        if parent.0.starts_with("/proc") {
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
        //sys.log(&format!("rename({}, {})", old_path, &new_path));
        let old_path = self._resolve_path(old_path, cwd);
        let new_path = self._resolve_path(new_path, cwd);
        if new_path.0.starts_with("/proc") {
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
        //sys.log(&format!("remove({})", path));
        let path = self._resolve_path(path, cwd);
        if path.0.starts_with("/proc") {
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

    pub fn open_file(
        &mut self,
        path: &str,
        cwd: u32,
        current_proc: &_Process,
        fd: u32,
    ) -> Result<(FilesystemId, u32)> {
        let path = self._resolve_path(path, cwd);
        if path.0.starts_with("/proc") {
            let inode_number = self.procfs.open_file(&path, current_proc, fd)?;
            Ok((FilesystemId::Proc, inode_number))
        } else {
            let inode_number = self.inode_mut_from_path(&path)?.inode_number;
            Ok((FilesystemId::Main, inode_number))
        }
    }

    pub fn close_file(
        &mut self,
        filesystem: FilesystemId,
        current_pid: u32,
        fd: u32,
    ) -> Result<()> {
        match filesystem {
            FilesystemId::Proc => self.procfs.close_file(current_pid, fd),
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
        current_process: &_Process,
        fd: u32,
        filesystem: FilesystemId,
        inode_number: u32,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        if filesystem == FilesystemId::Proc {
            return self.procfs.read_file_at_offset(
                current_process,
                fd,
                inode_number,
                buf,
                file_offset,
            );
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
        if path.0.starts_with("/proc") {
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
        if path.0.starts_with("/proc") {
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
                    .0
                    .clone();
                child_names.push(name);
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
        //sys.log("get_current_dir_name()");
        let inode = self
            .inode_from_number(inode_number)
            .expect("cwd valid inode");
        inode.path.clone()
    }

    fn _resolve_path<S: Into<String>>(&self, path: S, cwd_inode_number: u32) -> Path {
        let path = path.into();
        if path.starts_with('/') {
            // it's an absolute path
            Path(path)
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
        let processes = Arc::new(Mutex::new(Default::default()));
        let procfs = ProcFilesystem::new(Arc::clone(&processes));
        let mut vfs = VirtualFilesystemSwitch::new(procfs);
        vfs.create_file("/syslog", FileType::Regular, FilePermissions::ReadOnly, 0)
            .unwrap();
        vfs.create_file("/proc", FileType::Directory, FilePermissions::ReadOnly, 0)
            .unwrap();
        Self {
            vfs,
            next_pid: 0,
            processes,
        }
    }

    pub fn spawn_process(sys: Arc<Mutex<Self>>, process_name: String) -> Process {
        let pid = {
            let mut sys = sys.lock().expect("lock sys when spawning process");
            let pid = sys.next_pid;
            sys.next_pid += 1;
            pid
        };
        let proc = _Process {
            pid,
            name: process_name,
            sys: Some(sys),
            open_files: Default::default(),
            next_fd: 0,
            cwd: 0,
            log: vec![],
        };
        let proc = Arc::new(Mutex::new(proc));
        let cloned_proc = Arc::clone(&proc);
        {
            let proc = proc.lock().unwrap();
            let mut sys = proc.sys.as_ref().unwrap().lock().unwrap();
            sys.add_process(pid, cloned_proc);
        }
        Process(proc)
    }

    fn add_process(&mut self, pid: u32, process: Arc<Mutex<_Process>>) {
        let mut processes = self.processes.lock().unwrap();
        processes.insert(pid, process);
    }

    fn remove_process(&mut self, pid: u32) {
        let mut processes = self.processes.lock().unwrap();
        processes.remove(&pid);
    }
}

impl _Process {
    pub fn create<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<()> {
        let path = path.into();
        self.log.push(format!(
            "create({:?}, {:?}, {:?})",
            path, file_type, permissions
        ));
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.vfs.create_file(path, file_type, permissions, self.cwd)
    }

    pub fn rename<S: Into<String>>(&mut self, old_path: &str, new_path: S) -> Result<()> {
        let new_path = new_path.into();
        self.log
            .push(format!("rename({:?}, {:?})", old_path, new_path));

        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.vfs.rename_file(old_path, new_path, self.cwd)
    }

    pub fn remove(&mut self, path: &str) -> Result<()> {
        self.log.push(format!("remove({:?})", path));
        //TODO handle removing directories
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.vfs.remove_file(path, self.cwd)
    }

    pub fn open(&mut self, path: &str) -> Result<u32> {
        self.log.push(format!("open({:?})", path));
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        let fd = self.next_fd;
        let (filesystem, inode_number) = sys.vfs.open_file(path, self.cwd, &self, fd)?;
        self.next_fd += 1;
        self.open_files.push(OpenFile {
            filesystem,
            inode_number,
            fd,
            offset: 0,
        });
        Ok(fd)
    }

    pub fn close(&mut self, fd: u32) -> Result<()> {
        self.log.push(format!("close({})", fd));
        let open_file = self.take_open_file(fd)?;
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();

        sys.vfs.close_file(open_file.filesystem, self.pid, fd)
    }

    pub fn write(&mut self, fd: u32, buf: &[u8]) -> Result<()> {
        //TODO permissions
        self.log
            .push(format!("write({}, <{} bytes>)", fd, buf.len()));
        let arc_sys = self.sys.take().expect("sys");
        let mut open_file = self.find_open_file_mut(fd)?;
        {
            let mut sys = arc_sys.lock().unwrap();
            let num_written = sys.vfs.write_file_at_offset(
                open_file.filesystem,
                open_file.inode_number,
                buf,
                open_file.offset,
            )?;
            open_file.offset += num_written;
        }
        self.sys = Some(arc_sys);
        Ok(())
    }

    pub fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize> {
        self.log.push(format!("read({}, <buf>)", fd));
        let arc_sys = self.sys.take().expect("some sys");
        let result = {
            let mut sys = arc_sys.lock().unwrap();
            let mut open_file = self.take_open_file(fd)?;

            let result = sys.vfs.read_file_at_offset(
                self,
                fd,
                open_file.filesystem,
                open_file.inode_number,
                buf,
                open_file.offset,
            );

            if let Ok(num_read) = result {
                open_file.offset += num_read;
            }
            self.open_files.push(open_file);
            result
        };
        self.sys = Some(arc_sys);
        result
    }

    pub fn seek(&mut self, fd: u32, offset: usize) -> Result<()> {
        self.log.push(format!("seek({}, {})", fd, offset));
        let arc_sys = self.sys.take().expect("some sys");
        let open_file = self.find_open_file_mut(fd)?;
        open_file.offset = offset;
        self.sys = Some(arc_sys);
        Ok(())
    }

    pub fn stat(&mut self, path: &str) -> Result<FileStat> {
        self.log.push(format!("stat({:?})", path));
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.vfs.stat_file(path, self.cwd)
    }

    pub fn list_dir<S: Into<String>>(&mut self, path: S) -> Result<Vec<String>> {
        let path = path.into();
        self.log.push(format!("list_dir({:?})", path));
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.vfs.list_dir(path, self.cwd)
    }

    pub fn chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
        let path = path.into();
        self.log.push(format!("chdir({:?})", path));
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        self.cwd = sys.vfs.resolve_dir(path, self.cwd)?;
        Ok(())
    }

    pub fn get_current_dir_name(&mut self) -> Path {
        self.log.push("get_current_dir_name()".to_owned());
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.vfs.file_name(self.cwd)
    }

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

impl Process {
    pub fn create<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<()> {
        self.0.lock().unwrap().create(path, file_type, permissions)
    }

    pub fn rename<S: Into<String>>(&mut self, old_path: &str, new_path: S) -> Result<()> {
        self.0.lock().unwrap().rename(old_path, new_path)
    }

    pub fn remove(&mut self, path: &str) -> Result<()> {
        self.0.lock().unwrap().remove(path)
    }

    pub fn open(&mut self, path: &str) -> Result<u32> {
        self.0.lock().unwrap().open(path)
    }

    pub fn close(&mut self, fd: u32) -> Result<()> {
        self.0.lock().unwrap().close(fd)
    }

    pub fn write(&mut self, fd: u32, buf: &[u8]) -> Result<()> {
        self.0.lock().unwrap().write(fd, buf)
    }

    pub fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize> {
        self.0.lock().unwrap().read(fd, buf)
    }

    pub fn seek(&mut self, fd: u32, offset: usize) -> Result<()> {
        self.0.lock().unwrap().seek(fd, offset)
    }

    pub fn stat(&mut self, path: &str) -> Result<FileStat> {
        self.0.lock().unwrap().stat(path)
    }

    pub fn list_dir<S: Into<String>>(&mut self, path: S) -> Result<Vec<String>> {
        self.0.lock().unwrap().list_dir(path)
    }

    pub fn chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
        self.0.lock().unwrap().chdir(path)
    }

    pub fn get_current_dir_name(&mut self) -> Path {
        self.0.lock().unwrap().get_current_dir_name()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let proc = self.0.lock().unwrap();
        let mut sys = proc.sys.as_ref().expect("some sys").lock().unwrap();
        sys.remove_process(proc.pid);
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

    fn setup() -> Process {
        let sys = System::new();
        System::spawn_process(Arc::new(Mutex::new(sys)), "test".to_owned())
    }

    #[test]
    fn create() {
        let mut proc = setup();
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
    }

    #[test]
    fn rename_moving_file_between_directories() {
        let mut proc = setup();
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert!(proc.list_dir("/").unwrap().contains(&"/myfile".to_owned()));
        proc.create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.rename("/myfile", "/dir/moved").unwrap();
        assert!(!proc.list_dir("/").unwrap().contains(&"/myfile".to_owned()));
        assert_eq!(proc.list_dir("/dir").unwrap(), vec!["/dir/moved"]);
    }

    #[test]
    fn rename_with_relative_paths() {
        let mut proc = setup();
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert!(proc.list_dir("/").unwrap().contains(&"/myfile".to_owned()));
        proc.rename("myfile", "new_name").unwrap();
        assert!(proc
            .list_dir("/")
            .unwrap()
            .contains(&"/new_name".to_owned()));
    }

    #[test]
    fn write_seek_read() {
        let mut proc = setup();
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        let fd = proc.open("/myfile").unwrap();
        proc.write(fd, &[0, 10, 20, 30]).unwrap();
        let buf = &mut [0, 0];
        proc.seek(fd, 1).unwrap();
        let mut n = proc.read(fd, buf).unwrap();
        assert_eq!(buf, &[10, 20]);
        assert_eq!(n, 2);
        n = proc.read(fd, buf).unwrap();
        assert_eq!(buf, &[30, 20]);
        assert_eq!(n, 1);
        n = proc.read(fd, buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn stat_file() {
        let mut proc = setup();
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(proc.stat("/myfile").unwrap().size, 0);
        let fd = proc.open("/myfile").unwrap();
        proc.write(fd, &[1, 2, 3]).unwrap();
        assert_eq!(proc.stat("/myfile").unwrap().size, 3);
    }

    #[test]
    fn chdir() {
        let mut proc = setup();
        proc.create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.create("dir/x", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        proc.chdir("/dir").unwrap();
        assert_eq!(proc.list_dir(".").unwrap(), vec!["/dir/x"]);
    }
}
