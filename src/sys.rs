use std::io::{Cursor, Read};

#[derive(Debug)]
pub struct System {
    files: Vec<FileEntry>,
    next_inode: usize,
    open_files: Vec<OpenFile>,
    next_fd: usize,
}

#[derive(Debug)]
struct FileEntry {
    inode: usize,
    path: String,
    file: File,
}

#[derive(Debug)]
struct OpenFile {
    inode: usize,
    fd: usize,
    offset: usize,
}

impl System {
    pub fn new() -> Self {
        let root_dir = FileEntry {
            inode: 0,
            path: "/".to_owned(),
            file: File::new_dir(),
        };
        Self {
            files: vec![root_dir],
            next_inode: 1,
            open_files: Default::default(),
            next_fd: 0,
        }
    }

    pub fn create<S: Into<String>>(&mut self, path: S, file_type: FileType) {
        let path = path.into();

        let inode = self.next_inode;
        self.next_inode += 1;

        let parent = self._parent_dir(&path);
        parent.children.push(inode);
        let file = File::new(file_type);
        self.files.push(FileEntry { inode, path, file });
    }

    pub fn rename<S: Into<String>>(&mut self, old_path: &str, new_path: S) {
        let new_path = new_path.into();
        let file = self._find_file(old_path);
        file.path = new_path.clone();
        let inode = file.inode;

        let old_parent = self._parent_dir(old_path);
        old_parent.children.retain(|child| *child != inode);
        let new_parent = self._parent_dir(&new_path);
        new_parent.children.push(inode);
    }

    pub fn remove(&mut self, path: &str) {
        let inode = self._find_file(path).inode;
        self.files.retain(|f| f.path != path);
        let parent = self._parent_dir(path);
        parent.children.retain(|child| *child != inode);
    }

    pub fn open(&mut self, path: &str) -> usize {
        let inode = self._find_file(path).inode;
        let fd = self.next_fd;
        self.next_fd += 1;
        self.open_files.push(OpenFile {
            inode,
            fd,
            offset: 0,
        });
        fd
    }

    pub fn close(&mut self, fd: usize) {
        self.open_files.retain(|f| f.fd != fd);
    }

    pub fn write(&mut self, fd: usize, buf: &[u8]) {
        let open_file = self.open_files.iter_mut().find(|f| f.fd == fd).unwrap();
        let f = &mut self
            .files
            .iter_mut()
            .find(|f| f.inode == open_file.inode)
            .unwrap()
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
    }

    pub fn read(&mut self, fd: usize, buf: &mut [u8]) -> usize {
        let open_file = self.open_files.iter_mut().find(|f| f.fd == fd).unwrap();
        let f = &self
            .files
            .iter()
            .find(|f| f.inode == open_file.inode)
            .unwrap()
            .file;

        if let File::Regular(f) = f {
            let mut cursor = Cursor::new(&f.content);
            cursor.set_position(open_file.offset as u64);
            let num_read = cursor.read(buf).unwrap();
            open_file.offset += num_read;
            num_read
        } else {
            panic!("Can't read directory");
        }
    }

    pub fn seek(&mut self, fd: usize, offset: usize) {
        let open_file = self.open_files.iter_mut().find(|f| f.fd == fd).unwrap();
        open_file.offset = offset;
    }

    pub fn file_size(&self, path: &str) -> usize {
        let f = &self.files.iter().find(|f| f.path == path).unwrap().file;
        if let File::Regular(f) = f {
            f.content.len()
        } else {
            panic!("Can't get size of directory: {}", path);
        }
    }

    pub fn list_dir(&self, path: &str) -> Vec<String> {
        let f = &self.files.iter().find(|f| f.path == path).unwrap().file;
        let mut child_names = Vec::new();
        if let File::Dir(dir) = f {
            for id in &dir.children {
                let name = self
                    .files
                    .iter()
                    .find(|f| f.inode == *id)
                    .unwrap()
                    .path
                    .clone();
                child_names.push(name);
            }
            return child_names;
        } else {
            panic!("Can't read file as directory: {}", path);
        }
    }

    fn _parent_dir(&mut self, path: &str) -> &mut Directory {
        let (mut parent_path, _name) = path.rsplit_once('/').unwrap();
        if parent_path == "" {
            parent_path = "/";
        }
        let parent = &mut self._find_file(parent_path).file;
        match parent {
            File::Dir(ref mut dir) => dir,
            File::Regular(_) => panic!("{} is not a directory", parent_path),
        }
    }

    fn _find_file(&mut self, path: &str) -> &mut FileEntry {
        self.files
            .iter_mut()
            .find(|f| f.path == path)
            .expect(&format!("Not found: {}", path))
    }
}

#[derive(PartialEq)]
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
    fn create_file() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular);
    }

    #[test]
    fn move_file_between_directories() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular);
        assert_eq!(sys.list_dir("/"), vec!["/myfile"]);
        sys.create("/dir", FileType::Directory);
        assert_eq!(sys.list_dir("/"), vec!["/myfile", "/dir"]);
        sys.rename("/myfile", "/dir/moved");
        assert_eq!(sys.list_dir("/"), vec!["/dir"]);
        assert_eq!(sys.list_dir("/dir"), vec!["/dir/moved"]);
    }

    #[test]
    fn write_seek_read() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular);
        let fd = sys.open("/myfile");
        sys.write(fd, &[0, 10, 20, 30]);
        let buf = &mut [0, 0];
        sys.seek(fd, 1);
        let mut n = sys.read(fd, buf);
        assert_eq!(buf, &[10, 20]);
        assert_eq!(n, 2);
        n = sys.read(fd, buf);
        assert_eq!(buf, &[30, 20]);
        assert_eq!(n, 1);
        n = sys.read(fd, buf);
        assert_eq!(n, 0);
    }

    #[test]
    fn get_file_size() {
        let mut sys = System::new();
        sys.create("/myfile", FileType::Regular);
        assert_eq!(sys.file_size("/myfile"), 0);
        let fd = sys.open("/myfile");
        sys.write(fd, &[1, 2, 3]);
        assert_eq!(sys.file_size("/myfile"), 3);
    }
}
