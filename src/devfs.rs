use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId,
};
use crate::vfs::Filesystem;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
pub struct DevFilesystem {
    parent_inode_id: InodeIdentifier,
    root_inode: Inode,
    log_inode: Inode,
    null_inode: Inode,
    output_inode: Inode,
}

//TODO Instead of tracking each individual inode in every
//method, should we delegate to 'Device' structs that
//encapsulate the behaviour of a specific device?

impl DevFilesystem {
    pub fn new(parent_inode_id: InodeIdentifier) -> Self {
        let root_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 0,
            },
            parent_id: parent_inode_id,
            file_type: FileType::Directory,
            size: 0,
            permissions: FilePermissions::ReadOnly,
        };
        let log_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 1,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::ReadWrite,
        };
        let null_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 2,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::ReadWrite,
        };
        let output_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 3,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::ReadWrite,
        };

        Self {
            parent_inode_id,
            root_inode,
            log_inode,
            null_inode,
            output_inode,
        }
    }
}

impl Filesystem for DevFilesystem {
    fn create(
        &mut self,
        _parent_directory: InodeIdentifier,
        _file_type: FileType,
        _permissions: FilePermissions,
    ) -> Result<Ino> {
        Err("Can't create file on devfs".to_owned())
    }

    fn remove(&mut self, _inode_number: Ino) -> Result<()> {
        Err("Can't remove file on devfs".to_owned())
    }

    fn inode(&self, inode_number: Ino) -> Result<Inode> {
        match inode_number {
            0 => Ok(self.root_inode),
            1 => Ok(self.log_inode),
            2 => Ok(self.null_inode),
            3 => Ok(self.output_inode),
            _ => Err("No such inode on devfs".to_owned()),
        }
    }

    fn add_directory_entry(
        &mut self,
        _directory: Ino,
        _name: String,
        _child: InodeIdentifier,
    ) -> Result<()> {
        Err("Can't add directory entry on devfs".to_owned())
    }

    fn remove_directory_entry(&mut self, _directory: Ino, _child: InodeIdentifier) -> Result<()> {
        Err("Can't remove directory entry on devfs".to_owned())
    }

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>> {
        match directory {
            0 => Ok(vec![
                DirectoryEntry {
                    name: "log".to_owned(),
                    inode_id: self.log_inode.id,
                },
                DirectoryEntry {
                    name: "null".to_owned(),
                    inode_id: self.null_inode.id,
                },
                DirectoryEntry {
                    name: "output".to_owned(),
                    inode_id: self.output_inode.id,
                },
            ]),
            1 => Err("Not a directory".to_owned()),
            2 => Err("Not a directory".to_owned()),
            3 => Err("Not a directory".to_owned()),
            _ => Err("No such directory".to_owned()),
        }
    }

    fn update_inode_parent(
        &mut self,
        _inode_number: Ino,
        _new_parent: InodeIdentifier,
    ) -> Result<()> {
        panic!("We shouldn't get here? devfs update_inode_parent")
    }

    fn open(&mut self, inode_number: Ino, id: OpenFileId) -> Result<()> {
        eprintln!("devfs open({}, {:?})", inode_number, id);
        Ok(())
    }

    fn close(&mut self, id: OpenFileId) -> Result<()> {
        eprintln!("devfs close({:?})", id);
        Ok(())
    }

    fn read(
        &mut self,
        inode_number: Ino,
        _id: OpenFileId,
        _buf: &mut [u8],
        _file_offset: usize,
    ) -> Result<usize> {
        match inode_number {
            0 => Err("Can't read directory".to_owned()),
            1 => Ok(0),
            2 => Ok(0),
            3 => Ok(0),
            _ => Err("No such file".to_owned()),
        }
    }

    fn write(&mut self, inode_number: Ino, buf: &[u8], _file_offset: usize) -> Result<usize> {
        match inode_number {
            0 => Err("Can't write to directory".to_owned()),
            1 => {
                eprintln!("/dev/log: {}", String::from_utf8_lossy(buf));
                Ok(buf.len())
            }
            2 => {
                eprintln!("DEBUG: /dev/null: {}", String::from_utf8_lossy(buf));
                Ok(buf.len())
            }
            3 => {
                println!("{}", String::from_utf8_lossy(buf));
                Ok(buf.len())
            }
            _ => Err("No such file".to_owned()),
        }
    }
}
