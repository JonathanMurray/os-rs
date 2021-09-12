use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::time::Instant;

use crate::core::{Fd, FilePermissions, Ino, Pid};
use crate::sys::{self, Directory, File, FilesystemId, Inode, InodeIdentifier};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct ProcFilesystem {
    startup_time: Instant,
    file_contents: HashMap<(Pid, Fd), String>,
    proc_inode: Inode,
    status_inode: Inode,
}

impl ProcFilesystem {
    pub fn new(parent_inode_id: InodeIdentifier) -> Self {
        let mut proc_children = HashMap::new();

        let proc_inode_id = InodeIdentifier {
            filesystem_id: FilesystemId::Proc,
            number: 0,
        };
        let status_inode_id = InodeIdentifier {
            filesystem_id: FilesystemId::Proc,
            number: 1,
        };
        proc_children.insert("status".to_owned(), status_inode_id);
        Self {
            startup_time: Instant::now(),
            file_contents: HashMap::new(),
            proc_inode: Inode {
                parent_id: parent_inode_id,
                id: proc_inode_id,
                file: File::Dir(Directory {
                    children: proc_children,
                }),
                permissions: FilePermissions::ReadOnly,
            },
            status_inode: Inode {
                parent_id: proc_inode_id,
                id: status_inode_id,
                file: File::new_regular(),
                permissions: FilePermissions::ReadOnly,
            },
        }
    }

    pub fn open_file(&mut self, inode_number: Ino, fd: Fd) -> Result<()> {
        match inode_number {
            1 => {
                let content = self._status_file_content();
                let mut processes = sys::processes();
                let pid = processes.current().pid;
                self.file_contents.insert((pid, fd), content);
                Ok(())
            }
            0 => Err("Cannot open. Is directory".to_owned()),
            _ => Err("Cannot open. No such file".to_owned()),
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

    pub fn inode_mut(&mut self, inode_number: Ino) -> Result<&mut Inode> {
        // TODO: It feels weird that we'd need to hand out a "File" object here
        // We shouldn't be required to have the file contents prepared at this
        // point?
        match inode_number {
            0 => Ok(&mut self.proc_inode),
            1 => Ok(&mut self.status_inode),
            _ => Err(format!(
                "No file on procfs with inode number: {}",
                inode_number
            )),
        }
    }

    pub fn inode(&self, inode_number: Ino) -> Result<&Inode> {
        match inode_number {
            0 => Ok(&self.proc_inode),
            1 => Ok(&self.status_inode),
            _ => Err(format!(
                "No file on procfs with inode number: {}",
                inode_number
            )),
        }
    }

    pub fn read_file_at_offset(
        &mut self,
        fd: Fd,
        inode_number: Ino,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match inode_number {
            1 => {
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
            _ => panic!("no file in procfs with inode number {}", inode_number),
        }
    }

    fn _status_file_content(&self) -> String {
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
            content.push_str(&format!("     log: {:?}\n", proc.log));
        }
        content
    }
}
