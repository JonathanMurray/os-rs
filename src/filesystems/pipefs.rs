use std::cmp;
use std::collections::HashMap;

use crate::filesystems::{AccessMode, Filesystem, WriteError};
use crate::util::{
    FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier, OpenFileId, Uid,
};

const ROOT_INODE_NUMBER: Ino = 0;

#[derive(Debug)]
struct Pipe {
    buf: Vec<u8>,
    is_write_end_open: bool,
    is_read_end_open: bool,
}

impl Pipe {
    fn new() -> Self {
        // HACK: We assume that open will be called on any pipe
        // that is created, so we start with the values set to true.
        Self {
            buf: Default::default(),
            is_write_end_open: true,
            is_read_end_open: true,
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        let n = cmp::min(self.buf.len(), buf.len());

        if n == 0 {
            if self.is_write_end_open {
                // reading would block
                return None;
            } else {
                // EOF
                return Some(0);
            }
        }

        let consumed: Vec<u8> = self.buf.drain(..n).collect();
        buf[..n].copy_from_slice(&consumed[..]);
        Some(n)
    }

    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, WriteError> {
        // TODO control max pipe size
        self.buf.extend(buf);

        if self.is_read_end_open {
            Ok(buf.len())
        } else {
            Err(WriteError::PipeClosedAtReadEnd)
        }
    }
}

#[derive(Debug)]
pub struct PipeFilesystem {
    next_inode_number: Ino,
    pipes: HashMap<Ino, (Inode, Pipe)>,
    open_pipe_ends: HashMap<OpenFileId, (AccessMode, Ino)>,
}

impl PipeFilesystem {
    pub fn new() -> Self {
        Self {
            next_inode_number: ROOT_INODE_NUMBER + 1,
            pipes: Default::default(),
            open_pipe_ends: Default::default(),
        }
    }
}

type Result<T> = std::result::Result<T, String>;

impl Filesystem for PipeFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: ROOT_INODE_NUMBER,
        }
    }

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
        self.pipes
            .get(&inode_number)
            .map(|(inode, _pipe)| inode)
            .copied()
    }

    fn pipe(&mut self) -> Result<Ino> {
        let pipe = Pipe::new();
        let ino = self.next_inode_number;
        let inode = Inode {
            parent_id: InodeIdentifier {
                filesystem_id: FilesystemId::Pipe,
                number: ROOT_INODE_NUMBER,
            },
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Pipe,
                number: ino,
            },
            file_type: FileType::Pipe,
            size: 0,
            permissions: FilePermissions::new(0, 0), //TODO
            user_id: Uid(0),                         //TODO
        };
        self.pipes.insert(ino, (inode, pipe));
        eprintln!("DEBUG PIPEFS has {} PIPES", self.pipes.len());
        self.next_inode_number += 1;
        Ok(ino)
    }
    fn open(&mut self, inode_number: Ino, id: OpenFileId, access_mode: AccessMode) -> Result<()> {
        eprintln!(
            "pipefs open {:?}, {:?}, {:?}",
            inode_number, id, access_mode
        );

        assert!(access_mode != AccessMode::ReadWrite);
        self.open_pipe_ends.insert(id, (access_mode, inode_number));

        Ok(())
    }

    fn close(&mut self, id: OpenFileId) {
        eprintln!("pipefs close({:?})", id);
        let (access_mode, inode_number) = self.open_pipe_ends.remove(&id).unwrap();
        let (_inode, pipe) = self.pipes.get_mut(&inode_number).unwrap();
        if access_mode == AccessMode::WriteOnly {
            eprintln!("pipefs closing write-end of ({:?}, {:?})", inode_number, id);
            pipe.is_write_end_open = false;
        } else if access_mode == AccessMode::ReadOnly {
            eprintln!("pipefs closing read-end of ({:?}, {:?})", inode_number, id);
            pipe.is_read_end_open = false;
        }

        if !pipe.is_write_end_open && !pipe.is_read_end_open {
            self.pipes.remove(&inode_number).unwrap();
        }
    }

    fn read(
        &mut self,
        inode_number: Ino,
        _id: OpenFileId,
        buf: &mut [u8],
        _file_offset: usize,
    ) -> Result<Option<usize>> {
        let (_inode, pipe) = self.pipes.get_mut(&inode_number).unwrap();
        Ok(pipe.read(buf))
    }

    fn write(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        _file_offset: usize,
    ) -> std::result::Result<usize, WriteError> {
        let (_inode, pipe) = self.pipes.get_mut(&inode_number).unwrap();
        pipe.write(buf)
    }
}
