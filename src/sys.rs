use std::io::{Cursor, Read};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct System {
    inodes: Vec<Inode>,
    next_inode_number: usize,
    process: Process,
}

#[derive(Debug)]
struct Inode {
    inode_number: usize,
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
struct Process {
    open_files: Vec<OpenFile>,
    next_fd: usize,
    cwd: usize,
}

impl Process {
    fn open_file_mut(&mut self, fd: usize) -> Result<&mut OpenFile> {
        self.open_files
            .iter_mut()
            .find(|f| f.fd == fd)
            .ok_or_else(|| format!("No such fd: {}", fd))
    }
}

#[derive(Debug, Copy, Clone)]
struct OpenFile {
    inode_number: usize,
    fd: usize,
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
}

impl System {
    pub fn new() -> Self {
        let root_inode_number = 0;
        let root_dir = Inode {
            inode_number: root_inode_number,
            path: Path("/".to_owned()),
            file: File::new_dir(),
            permissions: FilePermissions::ReadOnly,
        };
        let process = Process {
            open_files: Default::default(),
            next_fd: 0,
            cwd: root_inode_number,
        };
        let mut sys = Self {
            inodes: vec![root_dir],
            next_inode_number: 1,
            process,
        };
        sys.create("/syslog", FileType::Regular, FilePermissions::ReadOnly)
            .unwrap();
        sys
    }

    fn log(&mut self, msg: &str) {
        if let Ok(file_entry) = self.inode_mut_from_path(&Path("/syslog".to_owned())) {
            if let File::Regular(f) = &mut file_entry.file {
                f.content.extend_from_slice(msg.as_bytes());
                f.content.push(b'\n');
            }
        }
    }

    pub fn create<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<()> {
        let path = path.into();
        self.log(&format!("create({:?}, {:?})", path, file_type));
        let path = self._resolve_path(path);
        let inode_number = self.next_inode_number;
        self.next_inode_number += 1;
        self._parent_dir(&path)?.children.push(inode_number);
        let file = File::new(file_type);
        self.inodes.push(Inode {
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
        self.log(&format!("rename({}, {})", old_path, &new_path));
        let old_path = self._resolve_path(old_path);
        let new_path = self._resolve_path(new_path);
        let file = self.inode_mut_from_path(&old_path)?;
        if file.permissions == FilePermissions::ReadOnly {
            return Err("Not permitted to rename file".to_owned());
        }

        file.path = new_path.clone();
        let inode_number = file.inode_number;

        let old_parent = self._parent_dir(&old_path)?;
        old_parent.children.retain(|child| *child != inode_number);
        let new_parent = self._parent_dir(&new_path)?;
        new_parent.children.push(inode_number);
        Ok(())
    }

    pub fn remove(&mut self, path: &str) -> Result<()> {
        //TODO handle removing directories
        self.log(&format!("remove({})", path));
        let path = self._resolve_path(path);
        let file_entry = self.inode_mut_from_path(&path)?;
        if file_entry.permissions == FilePermissions::ReadOnly {
            return Err("Not permitted to remove file".to_owned());
        }
        let inode_number = file_entry.inode_number;
        self.inodes.retain(|f| f.path != path);
        let parent = self._parent_dir(&path)?;
        parent.children.retain(|child| *child != inode_number);
        Ok(())
    }

    pub fn open(&mut self, path: &str) -> Result<usize> {
        self.log(&format!("open({})", path));
        let path = self._resolve_path(path);
        let inode_number = self.inode_mut_from_path(&path)?.inode_number;
        let fd = self.process.next_fd;
        self.process.next_fd += 1;
        self.process.open_files.push(OpenFile {
            inode_number,
            fd,
            offset: 0,
        });
        Ok(fd)
    }

    pub fn close(&mut self, fd: usize) -> Result<()> {
        self.log(&format!("close({})", fd));
        self.process.open_files.retain(|f| f.fd != fd);
        Ok(())
    }

    pub fn write(&mut self, fd: usize, buf: &[u8]) -> Result<()> {
        //TODO permissions
        self.log(&format!("write({}, ...)", fd));
        let open_file = self.process.open_file_mut(fd)?;
        let f = &mut self
            .inodes
            .iter_mut()
            .find(|f| f.inode_number == open_file.inode_number)
            .ok_or_else(|| "fd pointing to non-existent file".to_owned())?
            .file;
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
        Ok(())
    }

    pub fn read(&mut self, fd: usize, buf: &mut [u8]) -> Result<usize> {
        let syslog_inode_number = self
            .inode_mut_from_path(&Path("/syslog".to_owned()))
            .expect("No syslog file")
            .inode_number;
        let open_file = self.process.open_file_mut(fd)?;
        let f = &self
            .inodes
            .iter()
            .find(|f| f.inode_number == open_file.inode_number)
            .ok_or_else(|| "fd pointing to non-existent file".to_owned())?
            .file;

        let result = if let File::Regular(f) = f {
            let mut cursor = Cursor::new(&f.content);
            cursor.set_position(open_file.offset as u64);
            let num_read = cursor.read(buf).expect("Failed to read from file");
            open_file.offset += num_read;
            Ok(num_read)
        } else {
            Err("Can't read directory".to_owned())
        };
        if open_file.inode_number != syslog_inode_number {
            //Don't log syslog reads, as that may cause an infinite read
            self.log(&format!("read({}, ...)", fd));
        }
        result
    }

    pub fn seek(&mut self, fd: usize, offset: usize) -> Result<()> {
        self.log(&format!("seek({}, {})", fd, offset));
        let open_file = self.process.open_file_mut(fd)?;
        open_file.offset = offset;
        Ok(())
    }

    pub fn stat(&mut self, path: &str) -> Result<FileStat> {
        self.log(&format!("stat({})", path));
        let path = self._resolve_path(path);
        let file_entry = self.inode_mut_from_path(&path)?;
        let permissions = file_entry.permissions;
        if let File::Regular(f) = &file_entry.file {
            Ok(FileStat {
                file_type: FileType::Regular,
                size: Some(f.content.len()),
                permissions,
            })
        } else {
            Ok(FileStat {
                file_type: FileType::Directory,
                size: None,
                permissions,
            })
        }
    }

    pub fn list_dir<S: Into<String>>(&mut self, path: S) -> Result<Vec<String>> {
        let path = path.into();
        self.log(&format!("list_dir({})", path));
        let path = self._resolve_path(path);
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
            Err(format!("Can't read file as directory: {:?}", path))
        }
    }

    pub fn chdir<S: Into<String>>(&mut self, path: S) -> Result<()> {
        let path = path.into();
        self.log(&format!("chdir({})", path));
        let path = self._resolve_path(path);
        let inode = &self
            .inodes
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| format!("Directory not found: '{:?}'", path))?;
        if let File::Dir(_) = &inode.file {
            self.process.cwd = inode.inode_number;
            Ok(())
        } else {
            Err(format!("Not a directory: {:?}", path))
        }
    }

    fn _parent_dir(&mut self, path: &Path) -> Result<&mut Directory> {
        let parent_path = path.parent();
        let parent = &mut self.inode_mut_from_path(&parent_path)?.file;
        match parent {
            File::Dir(ref mut dir) => Ok(dir),
            File::Regular(_) => Err(format!("{:?} is not a directory", parent_path)),
        }
    }

    fn inode_mut_from_path(&mut self, path: &Path) -> Result<&mut Inode> {
        self.inodes
            .iter_mut()
            .find(|f| &f.path == path)
            .ok_or_else(|| format!("No inode with path: '{:?}'", path))
    }

    fn inode_from_number(&self, inode_number: usize) -> Result<&Inode> {
        self.inodes
            .iter()
            .find(|f| f.inode_number == inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }

    fn _resolve_path<S: Into<String>>(&self, path: S) -> Path {
        let path = path.into();
        if path.starts_with('/') {
            // it's an absolute path
            Path(path)
        } else {
            let cwd = self.process.cwd;
            let cwd_inode = self.inode_from_number(cwd).expect("cwd valid inode");
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
    children: Vec<usize>,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn create() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
    }

    #[test]
    fn rename_moving_file_between_directories() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(sys.list_dir("/").unwrap(), vec!["/syslog", "/myfile"]);
        sys.create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(
            sys.list_dir("/").unwrap(),
            vec!["/syslog", "/myfile", "/dir"]
        );
        sys.rename("/myfile", "/dir/moved").unwrap();
        assert_eq!(sys.list_dir("/").unwrap(), vec!["/syslog", "/dir"]);
        assert_eq!(sys.list_dir("/dir").unwrap(), vec!["/dir/moved"]);
    }

    #[test]
    fn rename_with_relative_paths() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(sys.list_dir("/").unwrap(), vec!["/syslog", "/myfile"]);
        sys.rename("myfile", "new_name").unwrap();
        assert_eq!(sys.list_dir("/").unwrap(), vec!["/syslog", "/new_name"]);
    }

    #[test]
    fn write_seek_read() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        let fd = sys.open("/myfile").unwrap();
        sys.write(fd, &[0, 10, 20, 30]).unwrap();
        let buf = &mut [0, 0];
        sys.seek(fd, 1).unwrap();
        let mut n = sys.read(fd, buf).unwrap();
        assert_eq!(buf, &[10, 20]);
        assert_eq!(n, 2);
        n = sys.read(fd, buf).unwrap();
        assert_eq!(buf, &[30, 20]);
        assert_eq!(n, 1);
        n = sys.read(fd, buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn stat_file() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        assert_eq!(
            sys.stat("/myfile").unwrap(),
            FileStat {
                file_type: FileType::Regular,
                size: Some(0),
                permissions: FilePermissions::ReadWrite,
            }
        );
        let fd = sys.open("/myfile").unwrap();
        sys.write(fd, &[1, 2, 3]).unwrap();
        assert_eq!(
            sys.stat("/myfile").unwrap(),
            FileStat {
                file_type: FileType::Regular,
                size: Some(3),
                permissions: FilePermissions::ReadWrite,
            }
        );
    }

    #[test]
    fn chdir() {
        let mut sys = System::new();
        sys.create("/dir", FileType::Directory, FilePermissions::ReadWrite)
            .unwrap();
        sys.create("dir/x", FileType::Regular, FilePermissions::ReadWrite)
            .unwrap();
        sys.chdir("/dir").unwrap();
        assert_eq!(sys.list_dir(".").unwrap(), vec!["/dir/x"]);
    }
}
