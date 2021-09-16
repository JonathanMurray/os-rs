use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::sync::MutexGuard;
use std::time::Instant;

use crate::sys::{GlobalProcessTable, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, Fd, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier, Pid,
};

type Result<T> = core::result::Result<T, String>;

fn lock_global_process_table() -> MutexGuard<'static, GlobalProcessTable> {
    // LOCKING: VFS must never be accessed while holding this lock
    GLOBAL_PROCESS_TABLE.lock().unwrap()
}

#[derive(Debug)]
pub struct ProcFilesystem {
    parent_inode_id: InodeIdentifier,
    startup_time: Instant,
    file_contents: HashMap<(Pid, Fd), String>,
    open_directories: HashSet<(Pid, Fd)>,
}

impl ProcFilesystem {
    pub fn new(parent_inode_id: InodeIdentifier) -> Self {
        Self {
            parent_inode_id,
            startup_time: Instant::now(),
            file_contents: HashMap::new(),
            open_directories: HashSet::new(),
        }
    }

    pub fn open_file(&mut self, inode_number: Ino, fd: Fd) -> Result<()> {
        match inode_number {
            1 => {
                let mut content = String::new();
                let uptime = Instant::now().duration_since(self.startup_time);
                content.push_str(&format!("uptime: {:.2}\n", uptime.as_secs_f32()));
                let process_table_lock = lock_global_process_table();
                let current_pid = process_table_lock.current_pid();
                content.push_str(&format!("{} processes:\n", process_table_lock.count()));
                for proc in process_table_lock.iter() {
                    if current_pid == proc.pid {
                        content.push_str(&format!("* {}: {}\n", proc.pid, proc.name));
                    } else {
                        content.push_str(&format!("  {}: {}\n", proc.pid, proc.name));
                    };

                    content.push_str(&format!("      {:?}\n", proc.state));
                    content.push_str(&format!("      open files: {:?}\n", proc.open_files));
                    content.push_str(&format!("      parent pid: {:?}\n", proc.parent_pid));
                }
                self.file_contents.insert((current_pid, fd), content);
                Ok(())
            }
            0 => {
                let process_table_lock = lock_global_process_table();
                let current_pid = process_table_lock.current_pid();
                self.open_directories.insert((current_pid, fd));
                Ok(())
            }
            _ => {
                if inode_number >= 1000 {
                    let mut process_table_lock = lock_global_process_table();
                    let pid = inode_number - 1000;

                    if let Some(proc) = process_table_lock.process(pid) {
                        let mut content = String::new();
                        content.push_str("Syscall log:\n");
                        for log_line in &proc.log {
                            content.push_str(log_line);
                            content.push('\n');
                        }
                        let current_pid = process_table_lock.current().pid;
                        self.file_contents.insert((current_pid, fd), content);
                        return Ok(());
                    } else {
                        println!("DEBUG: No process with pid: {}", pid);
                    }
                }

                return Err(format!(
                    "Cannot open. No file on procfs with inode number: {}",
                    inode_number
                ));
            }
        }
    }

    pub fn close_file(&mut self, fd: Fd) -> Result<()> {
        let mut process_table_lock = lock_global_process_table();
        let proc = process_table_lock.current();
        let closed_regular_file = self.file_contents.remove(&(proc.pid, fd)).is_some();
        if !closed_regular_file && !self.open_directories.remove(&(proc.pid, fd)) {
            return Err(format!("No file with fd: {}", fd));
        }

        Ok(())
    }

    pub fn inode(&self, inode_number: Ino) -> Result<Inode> {
        match inode_number {
            0 => Ok(Inode {
                parent_id: self.parent_inode_id,
                id: InodeIdentifier {
                    filesystem_id: FilesystemId::Proc,
                    number: 0,
                },
                file_type: FileType::Directory,
                size: 0,
                permissions: FilePermissions::ReadOnly,
            }),
            1 => Ok(Inode {
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
                permissions: FilePermissions::ReadOnly,
            }),
            _ => {
                if inode_number >= 1000 {
                    let mut process_table_lock = lock_global_process_table();
                    let pid = inode_number - 1000;

                    if process_table_lock.process(pid).is_some() {
                        return Ok(Inode {
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
                            permissions: FilePermissions::ReadOnly,
                        });
                    }
                }

                return Err(format!(
                    "No file on procfs with inode number: {}",
                    inode_number
                ));
            }
        }
    }

    pub fn list_directory(&mut self, inode_number: Ino) -> Result<Vec<DirectoryEntry>> {
        match inode_number {
            0 => {
                let mut listing = vec![DirectoryEntry {
                    inode_number: 1,
                    name: "status".to_owned(),
                    file_type: FileType::Regular,
                }];
                let process_table_lock = lock_global_process_table();
                let pid_files: Vec<DirectoryEntry> = process_table_lock
                    .iter()
                    .map(|proc| proc.pid)
                    .map(|pid| DirectoryEntry {
                        inode_number: 1000 + pid,
                        name: format!("{}", pid),
                        file_type: FileType::Regular,
                    })
                    .collect();
                listing.extend(pid_files);
                Ok(listing)
            }
            _ => Err(format!(
                "No directory on procfs with inode number: {}",
                inode_number
            )),
        }
    }

    pub fn directory_child_id(
        &mut self,
        dir_inode_number: Ino,
        child_name: &str,
    ) -> Result<InodeIdentifier> {
        match dir_inode_number {
            0 => {
                if child_name == "status" {
                    return Ok(InodeIdentifier {
                        filesystem_id: FilesystemId::Proc,
                        number: 1,
                    });
                }

                if let Ok(pid) = child_name.parse::<Pid>() {
                    let mut process_table_lock = lock_global_process_table();
                    if process_table_lock.process(pid).is_some() {
                        return Ok(InodeIdentifier {
                            filesystem_id: FilesystemId::Proc,
                            number: 1000 + pid,
                        });
                    }
                }

                return Err(format!("Directory has no child with name: {}", child_name));
            }
            _ => Err(format!(
                "No directory on procfs with inode number: {}",
                dir_inode_number
            )),
        }
    }

    pub fn read_file_at_offset(
        &mut self,
        fd: Fd,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        let mut process_table_lock = lock_global_process_table();
        let current_proc = process_table_lock.current();
        let content = self
            .file_contents
            .get(&(current_proc.pid, fd))
            .ok_or("No such open proc file")?;
        let mut cursor = Cursor::new(&content);
        cursor.set_position(file_offset as u64);
        let num_read = cursor.read(buf).expect("Failed to read from file");
        Ok(num_read)
    }
}
