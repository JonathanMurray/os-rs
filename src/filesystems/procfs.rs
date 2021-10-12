use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::MutexGuard;
use std::time::Instant;

use crate::sys::{GlobalProcessTable, IoctlRequest, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Pid, Uid,
};
use crate::filesystems::{AccessMode, WriteError, Filesystem};

fn lock_global_process_table() -> MutexGuard<'static, GlobalProcessTable> {
    // LOCKING: VFS must never be accessed while holding this lock
    GLOBAL_PROCESS_TABLE.lock().unwrap()
}

#[derive(Debug)]
enum File {
    Regular(String),
    Directory,
}

#[derive(Debug)]
pub struct ProcFilesystem {
    parent_inode_id: InodeIdentifier,
    startup_time: Instant,
    open_files: HashMap<OpenFileId, File>,
}

impl ProcFilesystem {
    pub fn new(parent_inode_id: InodeIdentifier) -> Self {
        Self {
            parent_inode_id,
            startup_time: Instant::now(),
            open_files: Default::default(),
        }
    }

    pub fn open_file(&mut self, inode_number: Ino, open_file_id: OpenFileId) -> Result<()> {
        match inode_number {
            1 => {
                let mut content = String::new();
                let uptime = Instant::now().duration_since(self.startup_time);
                content.push_str(&format!("uptime: {:.2}\n", uptime.as_secs_f32()));
                let process_table_lock = lock_global_process_table();
                content.push_str(&format!("{} processes:\n", process_table_lock.count()));
                let mut lines = Vec::new();
                for proc in process_table_lock.iter() {
                    let line = format!(
                        "{} {} {} {:?} {} {} {:?}\n",
                        proc.pid.0,
                        proc.parent_pid.0,
                        proc.args[0],
                        proc.state,
                        proc.uid.0,
                        proc.fds.len(),
                        proc.fds
                    );
                    lines.push((proc.pid, line));
                }
                lines.sort_by_key(|pair| pair.0 .0);
                for line in lines.into_iter().map(|pair| pair.1) {
                    content.push_str(&line);
                }
                self.open_files.insert(open_file_id, File::Regular(content));
                Ok(())
            }
            0 => {
                self.open_files.insert(open_file_id, File::Directory);
                Ok(())
            }
            _ => {
                if inode_number >= 1000 {
                    let mut process_table_lock = lock_global_process_table();
                    let pid = Pid(inode_number - 1000);

                    if let Some(proc) = process_table_lock.process(pid) {
                        let mut content = String::new();
                        content.push_str("Syscall log:\n");
                        for log_line in &proc.log {
                            content.push_str(log_line);
                            content.push('\n');
                        }
                        self.open_files.insert(open_file_id, File::Regular(content));
                        return Ok(());
                    } else {
                        eprintln!("WARN: No process with pid: {:?}", pid);
                    }
                }

                Err("No such inode".to_owned())
            }
        }
    }

    pub fn close_file(&mut self, open_file_id: OpenFileId) {
        self.open_files.remove(&open_file_id).unwrap();
    }

    pub fn inode(&self, inode_number: Ino) -> Option<Inode> {
        match inode_number {
            0 => Some(Inode {
                parent_id: self.parent_inode_id,
                id: InodeIdentifier {
                    filesystem_id: FilesystemId::Proc,
                    number: 0,
                },
                file_type: FileType::Directory,
                size: 0,
                permissions: FilePermissions::new(7, 5),
                user_id: Uid(0),
            }),
            1 => Some(Inode {
                parent_id: InodeIdentifier {
                    filesystem_id: FilesystemId::Proc,
                    number: 0,
                },
                id: InodeIdentifier {
                    filesystem_id: FilesystemId::Proc,
                    number: 1,
                },
                file_type: FileType::Regular,
                size: 0,
                permissions: FilePermissions::new(7, 4),
                user_id: Uid(0),
            }),
            _ => {
                if inode_number >= 1000 {
                    let mut process_table_lock = lock_global_process_table();
                    let pid = Pid(inode_number - 1000);

                    if process_table_lock.process(pid).is_some() {
                        return Some(Inode {
                            parent_id: InodeIdentifier {
                                filesystem_id: FilesystemId::Proc,
                                number: 0,
                            },
                            id: InodeIdentifier {
                                filesystem_id: FilesystemId::Proc,
                                number: inode_number,
                            },
                            file_type: FileType::Regular,
                            size: 0,
                            permissions: FilePermissions::new(7, 4),
                            user_id: Uid(0),
                        });
                    }
                }

                None
            }
        }
    }

    pub fn list_directory(&mut self, inode_number: Ino) -> Result<Vec<DirectoryEntry>> {
        match inode_number {
            0 => {
                let mut listing = vec![DirectoryEntry {
                    inode_id: InodeIdentifier::new(FilesystemId::Proc, 1),
                    name: "status".to_owned(),
                }];
                let process_table_lock = lock_global_process_table();
                let pid_files: Vec<DirectoryEntry> = process_table_lock
                    .iter()
                    .map(|proc| proc.pid)
                    .map(|pid| DirectoryEntry {
                        inode_id: InodeIdentifier::new(FilesystemId::Proc, 1000 + pid.0),
                        name: format!("{}", pid.0),
                    })
                    .collect();
                listing.extend(pid_files);
                Ok(listing)
            }
            _ => Err("No such inode".to_owned()),
        }
    }

    pub fn read_file_at_offset(
        &mut self,
        open_file_id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>> {
        let file = self
            .open_files
            .get(&open_file_id)
            .ok_or_else(|| format!("No open file on procfs with id: {:?}", open_file_id))?;
        if let File::Regular(content) = file {
            let mut cursor = Cursor::new(&content);
            cursor.set_position(file_offset as u64);
            let num_read = cursor.read(buf).expect("Failed to read from file");
            Ok(Some(num_read))
        } else {
            Err("No such inode".to_owned())
        }
    }
}

type Result<T> = std::result::Result<T, String>;

impl Filesystem for ProcFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        InodeIdentifier {
            filesystem_id: FilesystemId::Proc,
            number: 0,
        }
    }

    fn ioctl(&mut self, _inode_number: Ino, _req: IoctlRequest) -> Result<()> {
        Err("ioctl not supported".to_owned())
    }

    fn create(
        &mut self,
        _parent_directory: InodeIdentifier,
        _file_type: FileType,
        _permissions: FilePermissions,
    ) -> Result<Ino> {
        Err("Can't create file on procfs".to_owned())
    }

    fn truncate(&mut self, _inode_number: Ino) -> Result<()> {
        Err("Can't truncate file on procfs".to_owned())
    }

    fn remove(&mut self, _inode_number: Ino) -> Result<()> {
        Err("Can't remove file on procfs".to_owned())
    }

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
        self.inode(inode_number)
    }

    fn add_directory_entry(
        &mut self,
        _directory: Ino,
        _name: String,
        _child: InodeIdentifier,
    ) -> Result<()> {
        Err("Can't add directory entry on procfs".to_owned())
    }

    fn remove_directory_entry(&mut self, _directory: Ino, _child: InodeIdentifier) -> Result<()> {
        Err("Can't remove directory entry on procfs".to_owned())
    }

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>> {
        self.list_directory(directory)
    }

    fn update_inode_parent(&mut self, _inode_number: Ino, _new_parent: InodeIdentifier) -> bool {
        panic!("We shouldn't get here? procfs update_inode_parent")
    }

    fn open(
        &mut self,
        inode_number: Ino,
        open_file_id: OpenFileId,
        _access_mode: AccessMode,
    ) -> Result<()> {
        eprintln!("procfs open({}, {:?})", inode_number, open_file_id);
        self.open_file(inode_number, open_file_id)
    }

    fn close(&mut self, id: OpenFileId) {
        eprintln!("procfs close({:?})", id);
        self.close_file(id);
    }

    fn read(
        &mut self,
        _inode_number: Ino,
        id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>> {
        self.read_file_at_offset(id, buf, file_offset)
    }

    fn write(
        &mut self,
        _inode_number: Ino,
        _buf: &[u8],
        _file_offset: usize,
    ) -> std::result::Result<usize, WriteError> {
        Err(WriteError::Unexpected("Can't write to procfs".to_owned()))
    }
}
