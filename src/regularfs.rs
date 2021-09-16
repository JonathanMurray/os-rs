use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::util::{
    DirectoryEntry, Fd, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
};

type Result<T> = core::result::Result<T, String>;

type Directory = HashMap<String, InodeIdentifier>;
type RegularFile = Vec<u8>;

#[derive(Debug)]
enum FileContent {
    Dir(Directory),
    Regular(RegularFile),
}

#[derive(Debug)]
struct File {
    content: FileContent,
    fds: Vec<Fd>,
}

impl File {
    fn new(file_type: FileType) -> Self {
        match file_type {
            FileType::Directory => Self {
                content: FileContent::Dir(Default::default()),
                fds: Default::default(),
            },
            FileType::Regular => Self {
                content: FileContent::Regular(Default::default()),
                fds: Default::default(),
            },
        }
    }
}

#[derive(Debug)]
pub struct RegularFilesystem {
    inodes: Vec<Inode>,
    next_inode_number: Ino,
    files: HashMap<Ino, File>,
}

impl RegularFilesystem {
    pub fn new(root_inode: Inode) -> Self {
        let next_inode_number = root_inode.id.number + 1;
        let mut files = HashMap::new();
        files.insert(
            root_inode.id.number,
            File {
                content: FileContent::Dir(Default::default()),
                fds: Default::default(),
            },
        );
        Self {
            inodes: vec![root_inode],
            next_inode_number,
            files,
        }
    }

    pub fn create_inode(
        &mut self,
        file_type: FileType,
        permissions: FilePermissions,
        parent_id: InodeIdentifier,
    ) -> Ino {
        let inode_number = self.next_inode_number;
        self.next_inode_number += 1;
        let inode = Inode {
            parent_id,
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Main,
                number: inode_number,
            },
            file_type,
            size: 0,
            permissions,
        };
        self.inodes.push(inode);
        self.files.insert(inode_number, File::new(file_type));

        inode_number
    }

    pub fn remove_inode(&mut self, inode_number: Ino) {
        //TODO remove directory / regular file
        //TODO if someone has an open file, don't delete it in such a way that
        // read/writes start failing for that process
        self.inodes.retain(|inode| inode.id.number != inode_number);
    }

    fn directory_mut(&mut self, inode_number: Ino) -> Result<&mut Directory> {
        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err(format!("Not a directory: {}", inode_number)),
            None => Err(format!("No file with inode number: {}", inode_number)),
        }
    }

    fn directory(&self, inode_number: Ino) -> Result<&Directory> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err(format!("Not a directory: {}", inode_number)),
            None => Err(format!("No file with inode number: {}", inode_number)),
        }
    }

    pub fn add_child_to_directory(
        &mut self,
        dir_inode_number: Ino,
        name: String,
        child_inode_id: InodeIdentifier,
    ) -> Result<()> {
        let dir = self.directory_mut(dir_inode_number)?;
        dir.insert(name, child_inode_id);
        Ok(())
    }

    pub fn remove_child_from_directory(
        &mut self,
        dir_inode_number: Ino,
        child_inode_id: InodeIdentifier,
    ) -> Result<()> {
        let dir = self.directory_mut(dir_inode_number)?;
        dir.retain(|_name, child_id| *child_id != child_inode_id);
        Ok(())
    }

    pub fn set_inode_parent(
        &mut self,
        inode_number: Ino,
        new_parent_id: InodeIdentifier,
    ) -> Result<()> {
        self.inode_mut(inode_number)?.parent_id = new_parent_id;
        Ok(())
    }

    pub fn list_directory(&mut self, inode_number: Ino) -> Result<Vec<DirectoryEntry>> {
        let dir = self.directory(inode_number)?;
        let listing = dir
            .iter()
            .map(|(name, id)| {
                DirectoryEntry {
                    inode_number: id.number,
                    name: name.clone(),
                    file_type: FileType::Regular, //TODO
                }
            })
            .collect();
        Ok(listing)
    }

    pub fn directory_child_name(
        &self,
        dir_inode_number: Ino,
        child_inode_id: InodeIdentifier,
    ) -> Result<String> {
        let dir = self.directory(dir_inode_number)?;
        match dir
            .iter()
            .find(|(_name, child_id)| **child_id == child_inode_id)
        {
            Some(child) => Ok(child.0.clone()),
            None => Err(format!("No child with inode id: {:?}", child_inode_id)),
        }
    }

    pub fn directory_child_id(
        &mut self,
        dir_inode_number: Ino,
        child_name: &str,
    ) -> Result<InodeIdentifier> {
        let dir = self.directory(dir_inode_number)?;
        let child_id = dir
            .get(child_name)
            .ok_or_else(|| format!("No child with name: {}", child_name))?;
        Ok(*child_id)
    }

    pub fn open_file(&mut self, inode_number: Ino, fd: Fd) -> Result<()> {
        let file = self
            .files
            .get_mut(&inode_number)
            .ok_or_else(|| "No such file".to_owned())?;

        assert!(
            !file.fds.contains(&fd),
            "{} is already opened with fd {}",
            inode_number,
            fd
        );
        file.fds.push(fd);
        eprintln!("Opened inode {} with fd {}", inode_number, fd);
        Ok(())
    }

    pub fn close_file(&mut self, fd: Fd) -> Result<()> {
        for file in self.files.values_mut() {
            file.fds.retain(|open_fd| *open_fd != fd);
        }

        eprintln!("Closed fd {}", fd);
        Ok(())
    }

    pub fn read_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Regular(regular_file)) => {
                let mut cursor = Cursor::new(&regular_file);
                cursor.set_position(file_offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(num_read)
            }
            Some(FileContent::Dir(_)) => Err("It's a directory".to_owned()),
            None => Err("No such file".to_owned()),
        }
    }

    pub fn write_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        mut file_offset: usize,
    ) -> Result<usize> {
        //TODO permissions

        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Regular(f)) => {
                let mut num_written = 0;
                for &b in buf {
                    if file_offset < f.len() {
                        f[file_offset] = b;
                    } else {
                        f.push(b);
                    }
                    file_offset += 1;
                    num_written += 1;
                }

                self.inode_mut(inode_number)
                    .expect("Inode must exist at write")
                    .size = f.len();

                Ok(num_written)
            }
            Some(FileContent::Dir(_)) => Err("It's a directory".to_owned()),
            None => Err("No such file".to_owned()),
        }
    }

    fn inode_mut(&mut self, inode_number: Ino) -> Result<&mut Inode> {
        self.inodes
            .iter_mut()
            .find(|inode| inode.id.number == inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }

    pub fn inode(&self, inode_number: Ino) -> Result<Inode> {
        let inode = *self
            .inodes
            .iter()
            .find(|inode| inode.id.number == inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))?;
        Ok(inode)
    }
}
