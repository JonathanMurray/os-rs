use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};
use std::time::Instant;

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct System {
    inodes: Vec<Inode>,
    next_inode_number: u32,
    status_virtual_inode_number: u32,
    startup_time: Instant,
    num_processes: u32,
}

#[derive(Debug)]
struct Inode {
    inode_number: u32,
    path: Path,
    file: File,
    permissions: FilePermissions,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FilePermissions {
    ReadWrite,
    ReadOnly,
}

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: Option<usize>,
    pub permissions: FilePermissions,
}

#[derive(Debug)]
pub struct Process {
    sys: Option<Arc<Mutex<System>>>,
    open_files: Vec<OpenFile>,
    next_fd: u32,
    cwd: u32,
}

#[derive(Debug, Copy, Clone)]
struct OpenFile {
    inode_number: u32,
    fd: u32,
    offset: usize,
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

const ROOT_INODE_NUMBER: u32 = 0;

impl System {
    pub fn new() -> Self {
        let mut root_dir = Inode {
            inode_number: 0,
            path: Path("/".to_owned()),
            file: File::new_dir(),
            permissions: FilePermissions::ReadOnly,
        };
        let syslog_file = Inode {
            inode_number: 1,
            path: Path("/syslog".to_owned()),
            file: File::new_regular(),
            permissions: FilePermissions::ReadOnly,
        };
        let mut proc_dir = Inode {
            inode_number: 2,
            path: Path("/proc".to_owned()),
            file: File::new_dir(),
            permissions: FilePermissions::ReadOnly,
        };
        let status_file = Inode {
            inode_number: 3,
            path: Path("/proc/status".to_owned()),
            file: File::Virtual,
            permissions: FilePermissions::ReadOnly,
        };

        if let File::Dir(dir) = &mut root_dir.file {
            dir.children.push(syslog_file.inode_number);
            dir.children.push(proc_dir.inode_number);
        }
        if let File::Dir(dir) = &mut proc_dir.file {
            dir.children.push(status_file.inode_number);
        }
        Self {
            inodes: vec![root_dir, syslog_file, proc_dir, status_file],
            next_inode_number: 4,
            status_virtual_inode_number: 3,
            startup_time: Instant::now(),
            num_processes: 0,
        }
    }

    pub fn spawn_process(sys: Arc<Mutex<Self>>) -> Process {
        sys.lock()
            .expect("lock sys when spawning process")
            .num_processes += 1;
        Process {
            sys: Some(sys),
            open_files: Default::default(),
            next_fd: 0,
            cwd: ROOT_INODE_NUMBER,
        }
    }

    fn read_at_offset(
        &mut self,
        inode_number: u32,
        offset: usize,
        buf: &mut [u8],
    ) -> Result<usize> {
        let file = &self
            .inodes
            .iter()
            .find(|f| f.inode_number == inode_number)
            .ok_or_else(|| "fd pointing to non-existent file".to_owned())?
            .file;

        match file {
            File::Regular(regular_file) => {
                let mut cursor = Cursor::new(&regular_file.content);
                cursor.set_position(offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(num_read)
            }
            File::Virtual => {
                if inode_number == self.status_virtual_inode_number {
                    //Gives different data on subsequent reads of the same fd
                    //which is not great. The newline can be lost for example.
                    let uptime = Instant::now().duration_since(self.startup_time);
                    let content = format!("Uptime: {:.2}\nProcesses: {}\n", 
                        uptime.as_secs_f32(),
                        self.num_processes);
                    let mut cursor = Cursor::new(&content);
                    cursor.set_position(offset as u64);
                    let num_read = cursor.read(buf).expect("Failed to read from file");
                    Ok(num_read)
                } else {
                    panic!("No virtual file for inode number {}", inode_number)
                }
            }
            File::Dir(_) => Err("Can't read directory".to_owned()),
        }
    }

    fn log(&mut self, msg: &str) {
        if let Ok(file_entry) = self.inode_mut_from_path(&Path("/syslog".to_owned())) {
            if let File::Regular(f) = &mut file_entry.file {
                f.content.extend_from_slice(msg.as_bytes());
                f.content.push(b'\n');
            }
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

impl Process {
    fn find_open_file_mut(&mut self, fd: u32) -> Result<&mut OpenFile> {
        self.open_files
            .iter_mut()
            .find(|f| f.fd == fd)
            .ok_or_else(|| format!("No such fd: {}", fd))
    }

    fn find_open_file(&self, fd: u32) -> Result<&OpenFile> {
        self.open_files
            .iter()
            .find(|f| f.fd == fd)
            .ok_or_else(|| format!("No such fd: {}", fd))
    }

    pub fn create<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<()> {
        let path = path.into();
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("create({:?}, {:?})", path, file_type));
        let path = self._resolve_path(path, &sys);
        let inode_number = sys.next_inode_number;
        sys.next_inode_number += 1;
        sys.parent_dir(&path)?.children.push(inode_number);
        let file = File::new(file_type);
        sys.inodes.push(Inode {
            inode_number,
            path,
            file,
            permissions,
        });
        Ok(())
    }

    pub fn rename<S: Into<String>>(&mut self, old_path: &str, new_path: S) -> Result<()> {
        //TODO: handle replacing existing file
        let new_path = new_path.into();
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("rename({}, {})", old_path, &new_path));
        let old_path = self._resolve_path(old_path, &sys);
        let new_path = self._resolve_path(new_path, &sys);
        let file = sys.inode_mut_from_path(&old_path)?;
        if file.permissions == FilePermissions::ReadOnly {
            return Err("Not permitted to rename file".to_owned());
        }

        file.path = new_path.clone();
        let inode_number = file.inode_number;

        let old_parent = sys.parent_dir(&old_path)?;
        old_parent.children.retain(|child| *child != inode_number);
        let new_parent = sys.parent_dir(&new_path)?;
        new_parent.children.push(inode_number);
        Ok(())
    }

    pub fn remove(&mut self, path: &str) -> Result<()> {
        //TODO handle removing directories
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("remove({})", path));
        let path = self._resolve_path(path, &sys);
        let file_entry = sys.inode_mut_from_path(&path)?;
        if file_entry.permissions == FilePermissions::ReadOnly {
            return Err("Not permitted to remove file".to_owned());
        }
        let inode_number = file_entry.inode_number;
        sys.inodes.retain(|f| f.path != path);
        let parent = sys.parent_dir(&path)?;
        parent.children.retain(|child| *child != inode_number);
        Ok(())
    }

    pub fn open(&mut self, path: &str) -> Result<u32> {
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("open({})", path));
        let path = self._resolve_path(path, &sys);
        let inode_number = sys.inode_mut_from_path(&path)?.inode_number;
        let fd = self.next_fd;
        self.next_fd += 1;
        self.open_files.push(OpenFile {
            inode_number,
            fd,
            offset: 0,
        });
        Ok(fd)
    }

    pub fn close(&mut self, fd: u32) -> Result<()> {
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("close({})", fd));
        self.open_files.retain(|f| f.fd != fd);
        Ok(())
    }

    pub fn write(&mut self, fd: u32, buf: &[u8]) -> Result<()> {
        //TODO permissions
        let arc_sys = self.sys.take().expect("sys");
        arc_sys.lock().unwrap().log(&format!("write({}, ...)", fd));
        let open_file = self.find_open_file(fd)?;
        {
            let mut sys = arc_sys.lock().unwrap();
            let f = &mut sys
                .inodes
                .iter_mut()
                .find(|f| f.inode_number == open_file.inode_number)
                .ok_or_else(|| "fd pointing to non-existent file".to_owned())?
                .file;
            let open_file = self.find_open_file_mut(fd)?;
            if let File::Regular(ref mut f) = f {
                for &b in buf {
                    if open_file.offset < f.content.len() {
                        f.content[open_file.offset] = b;
                    } else {
                        f.content.push(b);
                    }
                    open_file.offset += 1;
                }
            }
        }
        self.sys = Some(arc_sys);
        Ok(())
    }

    pub fn read(&mut self, fd: u32, buf: &mut [u8]) -> Result<usize> {
        let arc_sys = self.sys.take().expect("some sys");
        let result = {
            let mut sys = arc_sys.lock().unwrap();
            let syslog_inode_number = sys
                .inode_mut_from_path(&Path("/syslog".to_owned()))
                .expect("No syslog file")
                .inode_number;
            let open_file = self.find_open_file_mut(fd)?;

            match sys.read_at_offset(open_file.inode_number, open_file.offset, buf) {
                Ok(num_read) => {
                    open_file.offset += num_read;
                    if open_file.inode_number != syslog_inode_number {
                        //Don't log syslog reads, as that may cause an infinite read
                        sys.log(&format!("read({}, ...)", fd));
                    }
                    Ok(num_read)
                }
                err => err,
            }
        };
        self.sys = Some(arc_sys);
        result
    }

    pub fn seek(&mut self, fd: u32, offset: usize) -> Result<()> {
        let arc_sys = self.sys.take().expect("some sys");
        arc_sys
            .lock()
            .unwrap()
            .log(&format!("seek({}, {})", fd, offset));
        let open_file = self.find_open_file_mut(fd)?;
        open_file.offset = offset;
        self.sys = Some(arc_sys);
        Ok(())
    }

    pub fn stat(&mut self, path: &str) -> Result<FileStat> {
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("stat({})", path));
        let path = self._resolve_path(path, &sys);
        let file_entry = sys.inode_mut_from_path(&path)?;
        let permissions = file_entry.permissions;
        match &file_entry.file {
            File::Regular(regular_file) => Ok(FileStat {
                file_type: FileType::Regular,
                size: Some(regular_file.content.len()),
                permissions,
            }),
            File::Dir(_) => Ok(FileStat {
                file_type: FileType::Directory,
                size: None,
                permissions,
            }),
            File::Virtual => Ok(FileStat {
                file_type: FileType::Regular,
                size: Some(0),
                permissions,
            }),
        }
    }

    pub fn list_dir<S: Into<String>>(&mut self, path: S) -> Result<Vec<String>> {
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        let path = path.into();
        sys.log(&format!("list_dir({})", path));
        let path = self._resolve_path(path, &sys);
        let f = &sys
            .inodes
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| format!("Directory not found: '{:?}'", path))?
            .file;
        let mut child_names = Vec::new();
        if let File::Dir(dir) = f {
            for &id in &dir.children {
                let name = sys
                    .inode_from_number(id)
                    .expect("child with valid inode")
                    .path
                    .0
                    .clone();
                child_names.push(name);
            }
            Ok(child_names)
        } else {
            Err(format!("Can't read file as directory: {:?}", path))
        }
    }

    pub fn chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
        let path = path.into();
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log(&format!("chdir({})", path));
        let path = self._resolve_path(path, &sys);
        let inode = &sys
            .inodes
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| format!("Directory not found: '{:?}'", path))?;
        if let File::Dir(_) = &inode.file {
            self.cwd = inode.inode_number;
            Ok(())
        } else {
            Err(format!("Not a directory: {:?}", path))
        }
    }

    pub fn get_current_dir_name(&mut self) -> Path {
        let mut sys = self.sys.as_ref().expect("some sys").lock().unwrap();
        sys.log("get_current_dir_name()");
        let cwd_inode = sys.inode_from_number(self.cwd).expect("cwd valid inode");
        cwd_inode.path.clone()
    }

    fn _resolve_path<S: Into<String>>(&self, path: S, sys: &System) -> Path {
        let path = path.into();
        if path.starts_with('/') {
            // it's an absolute path
            Path(path)
        } else {
            let cwd = self.cwd;
            let cwd_inode = sys.inode_from_number(cwd).expect("cwd valid inode");
            cwd_inode.path.clone().resolve(&path)
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum FileType {
    Regular,
    Directory,
}

#[derive(Debug)]
enum File {
    Regular(RegularFile),
    Dir(Directory),
    Virtual,
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

    #[test]
    fn create() {
        let sys = System::new();
        let mut proc = System::spawn_process(Arc::new(Mutex::new(sys)));
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
    }

    #[test]
    fn rename_moving_file_between_directories() {
        let sys = System::new();
        let mut proc = System::spawn_process(Arc::new(Mutex::new(sys)));
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
        let sys = System::new();

        let mut proc = System::spawn_process(Arc::new(Mutex::new(sys)));
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
        let sys = System::new();

        let mut proc = System::spawn_process(Arc::new(Mutex::new(sys)));
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
        let sys = System::new();

        let mut proc = System::spawn_process(Arc::new(Mutex::new(sys)));
        proc.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(
            proc.stat("/myfile").unwrap(),
            FileStat {
                file_type: FileType::Regular,
                size: Some(0),
                permissions: FilePermissions::ReadWrite,
            }
        );
        let fd = proc.open("/myfile").unwrap();
        proc.write(fd, &[1, 2, 3]).unwrap();
        assert_eq!(
            proc.stat("/myfile").unwrap(),
            FileStat {
                file_type: FileType::Regular,
                size: Some(3),
                permissions: FilePermissions::ReadWrite,
            }
        );
    }

    #[test]
    fn chdir() {
        let sys = System::new();

        let mut proc = System::spawn_process(Arc::new(Mutex::new(sys)));
        proc.create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        proc.create("dir/x", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        proc.chdir("/dir").unwrap();
        assert_eq!(proc.list_dir(".").unwrap(), vec!["/dir/x"]);
    }
}
