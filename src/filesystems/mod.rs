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

    fn inode(&self, _inode_number: Ino) -> Option<Inode>;

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

    // ---------------------------------------
    //     Optional functionality below
    // ---------------------------------------

    fn pipe(&mut self) -> Result<Ino> {
        unimplemented!("pipes")
    }

    fn ioctl(&mut self, _inode_number: Ino, _req: IoctlRequest) -> Result<()> {
        unimplemented!("ioctl")
    }

    fn create(
        &mut self,
        _parent_directory: InodeIdentifier,
        _file_type: FileType,
        _permissions: FilePermissions,
    ) -> Result<Ino> {
        unimplemented!("creating files")
    }

    fn truncate(&mut self, _inode_number: Ino) -> Result<()> {
        unimplemented!("truncating files")
    }

    fn remove(&mut self, _inode_number: Ino) -> Result<()> {
        unimplemented!("removing files")
    }

    fn add_directory_entry(
        &mut self,
        _directory: Ino,
        _name: String,
        _child: InodeIdentifier,
    ) -> Result<()> {
        unimplemented!("adding directory entries")
    }

    fn remove_directory_entry(&mut self, _directory: Ino, _child: InodeIdentifier) -> Result<()> {
        unimplemented!("removing directory entries")
    }

    fn directory_entries(&mut self, _directory: Ino) -> Result<Vec<DirectoryEntry>> {
        unimplemented!("listing directory entries")
    }

    fn update_inode_parent(&mut self, _inode_number: Ino, _new_parent: InodeIdentifier) -> bool {
        unimplemented!("updating inode parent")
    }
}
