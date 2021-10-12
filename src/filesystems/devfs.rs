use crate::filesystems::{AccessMode, Filesystem, WriteError};
use crate::sys::{IoctlRequest, Signal, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Pid, Uid,
};

use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

const INO_ROOT: Ino = 0;
const INO_LOG_DEVICE: Ino = 1;
const INO_NULL_DEVICE: Ino = 2;
const INO_TERMINAL_DEVICE: Ino = 3;

#[derive(Debug)]
pub struct DevFilesystem {
    parent_inode_id: InodeIdentifier,
    root_inode: Inode,
    devices: HashMap<Ino, (Inode, Box<dyn Device>)>,
}

impl DevFilesystem {
    pub fn new(
        parent_inode_id: InodeIdentifier,
        output: Arc<Mutex<Vec<u8>>>,
    ) -> (Self, TerminalInputFeeder) {
        let user_id = Uid(0);
        let root_inode = Inode {
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Dev,
                number: INO_ROOT,
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
                number: INO_LOG_DEVICE,
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
                number: INO_NULL_DEVICE,
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
                number: INO_TERMINAL_DEVICE,
            },
            parent_id: root_inode.id,
            file_type: FileType::CharacterDevice,
            size: 0,
            permissions: FilePermissions::new(7, 4),
            user_id,
        };

        let terminal_device = TerminalDevice {
            input_chunks: Default::default(),
            output,
            foreground_pid: Arc::new(Mutex::new(None)),
        };

        let terminal_input_feeder = TerminalInputFeeder {
            chunks: Arc::clone(&terminal_device.input_chunks),
            foreground_pid: Arc::clone(&terminal_device.foreground_pid),
        };

        let mut devices: HashMap<Ino, (Inode, Box<dyn Device>)> = HashMap::new();
        devices.insert(INO_LOG_DEVICE, (log_inode, Box::new(LogDevice)));
        devices.insert(INO_NULL_DEVICE, (null_inode, Box::new(NullDevice)));
        devices.insert(
            INO_TERMINAL_DEVICE,
            (terminal_inode, Box::new(terminal_device)),
        );

        let fs = Self {
            parent_inode_id,
            root_inode,
            devices,
        };

        (fs, terminal_input_feeder)
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

type Result<T> = std::result::Result<T, String>;

impl Filesystem for DevFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        self.root_inode.id
    }

    fn ioctl(&mut self, inode_number: Ino, req: IoctlRequest) -> Result<()> {
        let could_handle = self
            .devices
            .get(&inode_number)
            .map(|(_inode, device)| device.ioctl(req))
            .unwrap_or(false);

        if could_handle {
            Ok(())
        } else {
            Err("Does not support ioctl".to_owned())
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

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
        if inode_number == INO_ROOT {
            Some(self.root_inode)
        } else if let Some((inode, _device)) = self.devices.get(&inode_number) {
            Some(*inode)
        } else {
            None
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
        if directory == INO_ROOT {
            Ok(vec![
                DirectoryEntry {
                    name: "log".to_owned(),
                    inode_id: InodeIdentifier {
                        filesystem_id: FilesystemId::Dev,
                        number: INO_LOG_DEVICE,
                    },
                },
                DirectoryEntry {
                    name: "null".to_owned(),
                    inode_id: InodeIdentifier {
                        filesystem_id: FilesystemId::Dev,
                        number: INO_NULL_DEVICE,
                    },
                },
                DirectoryEntry {
                    name: "terminal".to_owned(),
                    inode_id: InodeIdentifier {
                        filesystem_id: FilesystemId::Dev,
                        number: INO_TERMINAL_DEVICE,
                    },
                },
            ])
        } else if self.devices.contains_key(&directory) {
            Err("not dir".to_owned())
        } else {
            Err("no such inode".to_owned())
        }
    }

    fn update_inode_parent(&mut self, _inode_number: Ino, _new_parent: InodeIdentifier) -> bool {
        panic!("We shouldn't get here? devfs update_inode_parent")
    }

    fn open(&mut self, inode_number: Ino, id: OpenFileId, _access_mode: AccessMode) -> Result<()> {
        eprintln!("devfs open({}, {:?})", inode_number, id);
        Ok(())
    }

    fn close(&mut self, id: OpenFileId) {
        eprintln!("devfs close({:?})", id);
    }

    fn read(
        &mut self,
        inode_number: Ino,
        _id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>> {
        if inode_number == INO_ROOT {
            Err("dir".to_owned())
        } else if let Some((_inode, device)) = self.devices.get_mut(&inode_number) {
            device.read(buf, file_offset)
        } else {
            Err("No such file".to_owned())
        }
    }

    fn write(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        file_offset: usize,
    ) -> std::result::Result<usize, WriteError> {
        if inode_number == INO_ROOT {
            Err(WriteError::Unexpected("dir".to_owned()))
        } else if let Some((_inode, device)) = self.devices.get_mut(&inode_number) {
            device
                .write(buf, file_offset)
                .map_err(WriteError::Unexpected)
        } else {
            Err(WriteError::Unexpected("no such inode".to_owned()))
        }
    }
}

trait Device: Send + std::fmt::Debug {
    fn ioctl(&self, _req: IoctlRequest) -> bool {
        false
    }

    fn read(&mut self, _buf: &mut [u8], _file_offset: usize) -> Result<Option<usize>>;

    fn write(&mut self, buf: &[u8], _file_offset: usize) -> Result<usize>;
}

#[derive(Debug)]
struct LogDevice;

impl Device for LogDevice {
    fn read(&mut self, _buf: &mut [u8], _file_offset: usize) -> Result<Option<usize>> {
        Ok(Some(0))
    }

    fn write(&mut self, buf: &[u8], _file_offset: usize) -> Result<usize> {
        eprintln!("/dev/log: {}", String::from_utf8_lossy(buf));
        Ok(buf.len())
    }
}

#[derive(Debug)]
struct NullDevice;

impl Device for NullDevice {
    fn read(&mut self, _buf: &mut [u8], _file_offset: usize) -> Result<Option<usize>> {
        Ok(Some(0))
    }

    fn write(&mut self, buf: &[u8], _file_offset: usize) -> Result<usize> {
        eprintln!("DEBUG: /dev/null: {}", String::from_utf8_lossy(buf));
        Ok(buf.len())
    }
}

#[derive(Debug)]
struct TerminalDevice {
    foreground_pid: Arc<Mutex<Option<Pid>>>,
    input_chunks: Arc<Mutex<VecDeque<Vec<u8>>>>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Device for TerminalDevice {
    fn ioctl(&self, req: IoctlRequest) -> bool {
        let IoctlRequest::SetTerminalForegroundProcess(pid) = req;
        *self.foreground_pid.lock().unwrap() = Some(pid);
        true
    }

    fn read(&mut self, buf: &mut [u8], _file_offset: usize) -> Result<Option<usize>> {
        let mut processes = GLOBAL_PROCESS_TABLE.lock().unwrap();

        let foreground_pid = *self.foreground_pid.lock().unwrap();
        if foreground_pid.as_ref() == Some(&processes.current().pid) {
            let mut terminal_input = self.input_chunks.lock().unwrap();
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
                    //eprintln!("DEBUG: devfs read terminal input: '{:?}'", &buf[..n]);
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

    fn write(&mut self, buf: &[u8], _file_offset: usize) -> Result<usize> {
        //eprintln!("DEBUG devfs terminal write: {:?}", buf);
        self.output.lock().unwrap().extend(buf);
        Ok(buf.len())
    }
}
