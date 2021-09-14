use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
};

type Result<T> = core::result::Result<T, String>;

type Directory = HashMap<String, InodeIdentifier>;
type RegularFile = Vec<u8>;

#[derive(Debug)]
pub struct RegularFilesystem {
    inodes: Vec<Inode>,
    next_inode_number: Ino,
    directories: HashMap<Ino, Directory>,
    regular_files: HashMap<Ino, RegularFile>,
}

impl RegularFilesystem {
    pub fn new(root_inode: Inode) -> Self {
        let next_inode_number = root_inode.id.number + 1;
        let mut directories = HashMap::new();
        directories.insert(root_inode.id.number, Default::default());
        let regular_files = HashMap::new();
        Self {
            inodes: vec![root_inode],
            next_inode_number,
            directories,
            regular_files,
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

        match file_type {
            FileType::Regular => {
                self.regular_files.insert(inode_number, Default::default());
            }
            FileType::Directory => {
                self.directories.insert(inode_number, Default::default());
            }
        }

        inode_number
    }

    pub fn remove_inode(&mut self, inode_id: InodeIdentifier) {
        //TODO remove directory / regular file
        self.inodes.retain(|inode| inode.id != inode_id);
    }

    fn directory_mut(&mut self, inode_number: Ino) -> Result<&mut Directory> {
        match self.directories.get_mut(&inode_number) {
            Some(dir) => Ok(dir),
            None => Err(format!("No directory with inode number: {}", inode_number)),
        }
    }

    fn directory(&self, inode_number: Ino) -> Result<&Directory> {
        match self.directories.get(&inode_number) {
            Some(dir) => Ok(dir),
            None => Err(format!("No directory with inode number: {}", inode_number)),
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

    pub fn read_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match self.regular_files.get(&inode_number) {
            Some(regular_file) => {
                let mut cursor = Cursor::new(&regular_file);
                cursor.set_position(file_offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(num_read)
            }
            None => Err("No such regular file".to_owned()),
        }
    }

    pub fn write_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        mut file_offset: usize,
    ) -> Result<usize> {
        //TODO permissions

        match self.regular_files.get_mut(&inode_number) {
            Some(f) => {
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

                self.inode_mut(inode_number).expect("Inode must exist").size = f.len();

                Ok(num_written)
            }
            None => Err("No such regular file".to_owned()),
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
