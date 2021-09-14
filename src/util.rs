/// inode number
pub type Ino = u32;

/// file descriptor
pub type Fd = u32;

/// process id
pub type Pid = u32;

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum FileType {
    Regular,
    Directory,
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
    pub inode_number: Ino,
    pub name: String,
    pub file_type: FileType,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FilesystemId {
    Main,
    Proc,
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
