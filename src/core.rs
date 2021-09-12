
/// inode number
pub type Ino = u32;

/// file descriptor
pub type Fd = u32;

/// process id
pub type Pid = u32;

#[derive(PartialEq, Debug)]
pub enum FileType {
    Regular,
    Directory,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum FilePermissions {
    ReadWrite,
    ReadOnly,
}
