use std::io::{Cursor, Read};

use crate::core::{FilePermissions, FileType, Ino};
use crate::sys::{File, FilesystemId, Inode, InodeIdentifier};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct RegularFilesystem {
    inodes: Vec<Inode>,
    next_inode_number: Ino,
}

impl RegularFilesystem {
    pub fn new(root_inode: Inode) -> Self {
        let next_inode_number = root_inode.id.number + 1;
        Self {
            inodes: vec![root_inode],
            next_inode_number,
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
        let file = File::new(file_type);
        let inode = Inode {
            parent_id,
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Main,
                number: inode_number,
            },
            file,
            permissions,
        };
        self.inodes.push(inode);
        inode_number
    }

    pub fn remove_inode(&mut self, inode_id: InodeIdentifier) {
        self.inodes.retain(|inode| inode.id != inode_id);
    }

    pub fn read_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        let file = &self.inode(inode_number)?.file;

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

    pub fn write_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        mut file_offset: usize,
    ) -> Result<usize> {
        //TODO permissions
        let file = &mut self.inode_mut(inode_number)?.file;
        let mut num_written = 0;
        if let File::Regular(ref mut f) = file {
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

    pub fn inode_mut(&mut self, inode_number: Ino) -> Result<&mut Inode> {
        self.inodes
            .iter_mut()
            .find(|inode| inode.id.number == inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }

    pub fn inode(&self, inode_number: Ino) -> Result<&Inode> {
        self.inodes
            .iter()
            .find(|inode| inode.id.number == inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }
}
