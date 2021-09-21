//TODO: Make all these into value structs?

/// inode number. Only unique per filesystem
pub type Ino = u32;

/// file descriptor. Only unique per process
pub type Fd = u32;

/// identifies an entry in the 'open files' VFS table. Globally unique
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct OpenFileId(pub u32);

/// process id
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct Pid(pub u32);

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum FileType {
    Regular,
    Directory,
    CharacterDevice,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FilePermissions {
    ReadWrite,
    ReadOnly,
}

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
    pub inode_id: InodeIdentifier,
}

#[derive(PartialEq, Debug)]
pub struct DirectoryEntry {
    pub inode_id: InodeIdentifier,
    pub name: String,
    pub file_type: FileType,
}

#[derive(Debug, Copy, Clone, PartialEq, Hash, std::cmp::Eq)]
pub enum FilesystemId {
    Main,
    Proc,
    Dev,
}

#[derive(Debug, Copy, Clone)]
pub struct Inode {
    pub parent_id: InodeIdentifier,
    pub id: InodeIdentifier,
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
}

impl Inode {
    pub fn is_dir(&self) -> bool {
        self.file_type == FileType::Directory
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct InodeIdentifier {
    pub filesystem_id: FilesystemId,
    pub number: Ino,
}

impl InodeIdentifier {
    pub fn new(filesystem_id: FilesystemId, number: Ino) -> Self {
        Self {
            filesystem_id,
            number,
        }
    }
}
