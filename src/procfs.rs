use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::time::Instant;

use crate::core::{Fd, FilePermissions, FileType, Ino, Pid};
use crate::sys::{self, FilesystemId, Inode, InodeIdentifier};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct ProcFilesystem {
    parent_inode_id: InodeIdentifier,
    startup_time: Instant,
    file_contents: HashMap<(Pid, Fd), String>,
}

impl ProcFilesystem {
    pub fn new(parent_inode_id: InodeIdentifier) -> Self {
        Self {
            parent_inode_id,
            startup_time: Instant::now(),
            file_contents: HashMap::new(),
        }
    }

    pub fn open_file(&mut self, inode_number: Ino, fd: Fd) -> Result<()> {
        match inode_number {
            1 => {
                let mut content = String::new();
                let uptime = Instant::now().duration_since(self.startup_time);
                content.push_str(&format!("uptime: {:.2}\n", uptime.as_secs_f32()));
                let processes = sys::processes();
                let current_pid = processes.currently_running_pid.unwrap();
                content.push_str(&format!("{} processes:\n", processes.processes.len()));
                for (pid, proc) in processes.processes.iter() {
                    if &current_pid == pid {
                        content.push_str(&format!("* {}: {}\n", proc.pid, proc.name));
                    } else {
                        content.push_str(&format!("  {}: {}\n", pid, proc.name));
                    };
                    content.push_str(&format!("    open files: {:?}\n", proc.open_files));
                }
                self.file_contents.insert((current_pid, fd), content);
                Ok(())
            }
            0 => Err("Cannot open. Is directory".to_owned()),
            _ => {
                if inode_number >= 1000 {
                    let mut processes = sys::processes();
                    let pid = inode_number - 1000;

                    if let Some(proc) = processes.processes.get(&pid) {
                        let mut content = String::new();
                        content.push_str("Syscall log:\n");
                        for log_line in &proc.log {
                            content.push_str(log_line);
                            content.push('\n');
                        }
                        let current_pid = processes.current().pid;
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
        let mut processes = sys::processes();
        let proc = processes.current();
        self.file_contents
            .remove(&(proc.pid, fd))
            .map(|_| ())
            .ok_or_else(|| "No such open file".to_owned())
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
                    let processes = sys::processes();
                    let pid = inode_number - 1000;

                    if processes.processes.contains_key(&pid) {
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

    pub fn list_directory(&mut self, inode_number: Ino) -> Result<Vec<String>> {
        match inode_number {
            0 => {
                let mut children = vec!["status".to_owned()];
                let processes = sys::processes();
                let pids: Vec<String> = processes
                    .processes
                    .keys()
                    .map(|pid| format!("{}", pid))
                    .collect();
                children.extend(pids);
                Ok(children)
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
                    let processes = sys::processes();
                    if processes.processes.contains_key(&pid) {
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
        let mut processes = sys::processes();
        let current_proc = processes.current();
        let content = self
            .file_contents
            .get(&(current_proc.pid, fd))
            .expect("No such open proc file");
        let mut cursor = Cursor::new(&content);
        cursor.set_position(file_offset as u64);
        let num_read = cursor.read(buf).expect("Failed to read from file");
        Ok(num_read)
    }
}
