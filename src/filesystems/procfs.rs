use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::MutexGuard;
use std::time::Instant;

use crate::filesystems::{AccessMode, Filesystem, WriteError};
use crate::sys::{GlobalProcessTable, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Pid, Uid,
};

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
}

type Result<T> = std::result::Result<T, String>;

impl Filesystem for ProcFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        InodeIdentifier {
            filesystem_id: FilesystemId::Proc,
            number: 0,
        }
    }

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
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

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>> {
        match directory {
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

    fn open(
        &mut self,
        inode_number: Ino,
        open_file_id: OpenFileId,
        _access_mode: AccessMode,
    ) -> Result<()> {
        eprintln!("procfs open({}, {:?})", inode_number, open_file_id);

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

    fn close(&mut self, id: OpenFileId) {
        eprintln!("procfs close({:?})", id);
        self.open_files.remove(&id).unwrap();
    }

    fn read(
        &mut self,
        _inode_number: Ino,
        id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>> {
        let file = self
            .open_files
            .get(&id)
            .ok_or_else(|| format!("No open file on procfs with id: {:?}", id))?;
        if let File::Regular(content) = file {
            let mut cursor = Cursor::new(&content);
            cursor.set_position(file_offset as u64);
            let num_read = cursor.read(buf).expect("Failed to read from file");
            Ok(Some(num_read))
        } else {
            Err("No such inode".to_owned())
        }
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
