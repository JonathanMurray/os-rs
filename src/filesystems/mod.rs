pub mod devfs;
pub mod pipefs;
pub mod procfs;
pub mod regularfs;

use crate::sys::IoctlRequest;
use crate::util::{
    DirectoryEntry, FilePermissions, FileType, Ino, Inode, InodeIdentifier, OpenFileId,
};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Eq, PartialEq)]
pub enum AccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Debug)]
pub enum WriteError {
    PipeClosedAtReadEnd,
    Unexpected(String),
}

pub trait Filesystem: std::fmt::Debug + Send {
    fn root_inode_id(&self) -> InodeIdentifier;

    fn pipe(&mut self) -> Result<Ino> {
        Err("Only pipefs supports pipes".to_owned())
    }

    fn ioctl(&mut self, inode_number: Ino, req: IoctlRequest) -> Result<()>;

    fn create(
        &mut self,
        parent_directory: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<Ino>;

    fn truncate(&mut self, inode_number: Ino) -> Result<()>;

    fn remove(&mut self, inode_number: Ino) -> Result<()>;

    fn inode(&self, inode_number: Ino) -> Option<Inode>;

    fn add_directory_entry(
        &mut self,
        directory: Ino,
        name: String,
        child: InodeIdentifier,
    ) -> Result<()>;

    fn remove_directory_entry(&mut self, directory: Ino, child: InodeIdentifier) -> Result<()>;

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>>;

    fn update_inode_parent(&mut self, inode_number: Ino, new_parent: InodeIdentifier) -> bool;

    fn open(&mut self, inode_number: Ino, id: OpenFileId, access_mode: AccessMode) -> Result<()>;

    fn close(&mut self, id: OpenFileId);

    fn read(
        &mut self,
        inode_number: Ino,
        id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>>;

    fn write(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        file_offset: usize,
    ) -> std::result::Result<usize, WriteError>;
}
