use crate::sys::{IoctlRequest, Signal, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Pid, Uid,
};
use crate::vfs::Filesystem;

use std::collections::VecDeque;
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
pub struct DevFilesystem {
    parent_inode_id: InodeIdentifier,
    root_inode: Inode,
    log_inode: Inode,
    null_inode: Inode,
    terminal_inode: Inode,
    terminal_input_chunks: Arc<Mutex<VecDeque<Vec<u8>>>>,
    terminal_output: Arc<Mutex<Vec<u8>>>,
    terminal_foreground_pid: Arc<Mutex<Option<Pid>>>,
}

//TODO Instead of tracking each individual inode in every
//method, should we delegate to 'Device' structs that
//encapsulate the behaviour of a specific device?

impl DevFilesystem {
    pub fn new(parent_inode_id: InodeIdentifier, terminal_output: Arc<Mutex<Vec<u8>>>) -> Self {
        let user_id = Uid(0);
        let root_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 0,
            },
            parent_id: parent_inode_id,
            file_type: FileType::Directory,
            size: 0,
            permissions: FilePermissions::new(7, 5),
            user_id,
        };
        let log_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 1,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::new(7, 4),
            user_id,
        };
        let null_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 2,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::new(7, 4),
            user_id,
        };
        let terminal_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: 3,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::new(7, 4),
            user_id,
        };

        Self {
            parent_inode_id,
            root_inode,
            log_inode,
            null_inode,
            terminal_inode,
            terminal_input_chunks: Default::default(),
            terminal_output,
            terminal_foreground_pid: Arc::new(Mutex::new(None)),
        }
    }

    pub fn terminal_input_feeder(&self) -> TerminalInputFeeder {
        TerminalInputFeeder {
            chunks: Arc::clone(&self.terminal_input_chunks),
            foreground_pid: Arc::clone(&self.terminal_foreground_pid),
        }
    }
}

pub struct TerminalInputFeeder {
    chunks: Arc<Mutex<VecDeque<Vec<u8>>>>,
    foreground_pid: Arc<Mutex<Option<Pid>>>,
}
impl TerminalInputFeeder {
    pub fn feed_bytes(&mut self, buf: Vec<u8>) {
        eprintln!("Got chunk from terminal driver: {:?}", buf);
        self.chunks.lock().unwrap().push_back(buf);
    }

    pub fn trigger_interrupt(&mut self) {
        eprintln!("DEBUG: devfs received interrupt");
        let mut processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
        let pid = *self.foreground_pid.lock().unwrap();
        let pid = pid.expect("There should be a foreground process by now");
        processes.process(pid).unwrap().signal(Signal::Interrupt);
    }
}

impl Filesystem for DevFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        self.root_inode.id
    }

    fn ioctl(&mut self, inode_number: Ino, req: IoctlRequest) -> Result<()> {
        match req {
            IoctlRequest::SetTerminalForegroundProcess(pid) => match inode_number {
                3 => {
                    *self.terminal_foreground_pid.lock().unwrap() = Some(pid);
                    Ok(())
                }
                _ => Err("Fd does not support ioctl".to_owned()),
            },
        }
    }

    fn create(
        &mut self,
        _parent_directory: InodeIdentifier,
        _file_type: FileType,
        _permissions: FilePermissions,
    ) -> Result<Ino> {
        Err("Can't create file on devfs".to_owned())
    }

    fn truncate(&mut self, _inode_number: Ino) -> Result<()> {
        Err("Can't truncate file on devfs".to_owned())
    }

    fn remove(&mut self, _inode_number: Ino) -> Result<()> {
        Err("Can't remove file on devfs".to_owned())
    }

    fn inode(&self, inode_number: Ino) -> Result<Inode> {
        match inode_number {
            0 => Ok(self.root_inode),
            1 => Ok(self.log_inode),
            2 => Ok(self.null_inode),
            3 => Ok(self.terminal_inode),
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
                    name: "terminal".to_owned(),
                    inode_id: self.terminal_inode.id,
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
        buf: &mut [u8],
        _file_offset: usize,
    ) -> Result<Option<usize>> {
        match inode_number {
            0 => Err("Can't read directory".to_owned()),
            1 => Ok(Some(0)),
            2 => Ok(Some(0)),
            3 => {
                let mut processes = GLOBAL_PROCESS_TABLE.lock().unwrap();

                let foreground_pid = *self.terminal_foreground_pid.lock().unwrap();
                if foreground_pid.as_ref() == Some(&processes.current().pid) {
                    let mut terminal_input = self.terminal_input_chunks.lock().unwrap();
                    match terminal_input.front_mut() {
                        Some(input_chunk) => {
                            let mut cursor = Cursor::new(&input_chunk[..]);
                            let n = cursor
                                .read(buf)
                                .map_err(|e| format!("Failed to read: {}", e))?;
                            input_chunk.drain(0..n);
                            if input_chunk.is_empty() {
                                // We read the entire chunk, so remove it from the queue
                                terminal_input.pop_front();
                            }
                            eprintln!("DEBUG: devfs read terminal input: '{:?}'", &buf[..n]);
                            Ok(Some(n))
                        }
                        None => {
                            //TODO: should we use async processes instead and return a Future
                            //here that triggers / wakes up when the kernel puts more data
                            // on stdin?

                            //Indicates that we'd need to block to receive data

                            Ok(None)
                        }
                    }
                } else {
                    // The reader is not the terminal's foreground process.
                    // We return None to block it from reading.
                    Ok(None)
                }
            }
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
                eprintln!("DEBUG devfs terminal write: {:?}", buf);
                self.terminal_output.lock().unwrap().extend(buf);
                Ok(buf.len())
            }
            _ => Err("No such file".to_owned()),
        }
    }
}
