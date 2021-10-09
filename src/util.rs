use std::fmt;
use std::fmt::Display;

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

/// user id
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct Uid(pub u32);

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum FileType {
    Regular,
    Directory,
    CharacterDevice,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct FilePermissions {
    owner: u8,
    others: u8,
}

impl FilePermissions {
    pub fn new(owner: u8, others: u8) -> Self {
        assert!(owner < 8, "Must be a 3-bit number");
        assert!(others < 8, "Must be a 3-bit number");
        Self { owner, others }
    }

    pub fn owner_write(&self) -> bool {
        self.owner & 2 != 0
    }

    pub fn others_write(&self) -> bool {
        self.others & 2 != 0
    }
}

impl Display for FilePermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(6);
        s.push(if self.owner & 4 != 0 { 'r' } else { '-' });
        s.push(if self.owner & 2 != 0 { 'w' } else { '-' });
        s.push(if self.owner & 1 != 0 { 'x' } else { '-' });
        s.push(if self.others & 4 != 0 { 'r' } else { '-' });
        s.push(if self.others & 2 != 0 { 'w' } else { '-' });
        s.push(if self.others & 1 != 0 { 'x' } else { '-' });
        write!(f, "{}", s)
    }
}

#[derive(PartialEq, Debug)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: usize,
    pub permissions: FilePermissions,
    pub inode_id: InodeIdentifier,
    pub user_id: Uid,
}

#[derive(PartialEq, Debug)]
pub struct DirectoryEntry {
    pub inode_id: InodeIdentifier,
    pub name: String,
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
    pub user_id: Uid,
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

#[derive(Debug)]
pub enum Ecode {
    /// Permission denied
    Eacces,

    /// Interrupted
    Eintr,

    /// Is directory
    Eisdir,

    /// Not a directory
    Enotdir,

    /// No such file or directory
    Enoent,

    /// Inappropriate I/O control operation
    Enotty,

    /// Bad file descriptor
    Ebadf,

    /// File exists
    Eexist,

    /// No such process
    Esrch,

    /// Operation not permitted
    Eperm,

    /// Improper link
    Exdev,

    Custom(String),
}

impl std::fmt::Display for Ecode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Ecode::Eacces => write!(f, "Permission denied"),
            Ecode::Eintr => write!(f, "Interrupted"),
            Ecode::Eisdir => write!(f, "Is a directory"),
            Ecode::Enotdir => write!(f, "Not a directory"),
            Ecode::Enoent => write!(f, "No such file or directory"),
            Ecode::Enotty => write!(f, "Inappropriate I/O control operation"),
            Ecode::Ebadf => write!(f, "Bad file descriptor"),
            Ecode::Eexist => write!(f, "File exists"),
            Ecode::Esrch => write!(f, "No such process"),
            Ecode::Eperm => write!(f, "Operation not permitted"),
            Ecode::Exdev => write!(f, "Improper link"),
            Ecode::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl From<Ecode> for String {
    fn from(ecode: Ecode) -> Self {
        format!("{}", ecode)
    }
}

pub type SysResult<T> = core::result::Result<T, Ecode>;
