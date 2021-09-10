use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::time::Instant;

use crate::core::{FilePermissions, FileType, Path};
use crate::sys::{self, FileStat};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct ProcFilesystem {
    startup_time: Instant,
    file_contents: HashMap<(u32, u32), String>,
}

impl ProcFilesystem {
    pub fn new() -> Self {
        Self {
            startup_time: Instant::now(),
            file_contents: HashMap::new(),
        }
    }

    pub fn open_file(&mut self, path: &Path, fd: u32) -> Result<u32> {
        match path.as_str() {
            s if s == "/proc/status" => {
                let content = self._status_file_content();
                let mut processes = sys::processes();
                let pid = processes.current().pid;
                self.file_contents.insert((pid, fd), content);
                let inode = 0;
                Ok(inode)
            }
            s if s == "/proc" => Err("Cannot open. Is directory".to_owned()),
            _ => Err("Cannot open. No such file".to_owned()),
        }
    }

    pub fn close_file(&mut self, fd: u32) -> Result<()> {
        let mut processes = sys::processes();
        let proc = processes.current();
        self.file_contents
            .remove(&(proc.pid, fd))
            .map(|_| ())
            .ok_or_else(|| "No such open file".to_owned())
    }

    pub fn read_file_at_offset(
        &mut self,
        fd: u32,
        inode_number: u32,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match inode_number {
            0 => {
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

    pub fn stat_file(&mut self, path: &Path) -> Result<FileStat> {
        let filesystem = "procfs".to_owned();
        match path.as_str() {
            s if s == "/proc/status" => Ok(FileStat {
                file_type: FileType::Regular,
                size: 0,
                permissions: FilePermissions::ReadOnly,
                inode_number: 0,
                filesystem,
            }),
            s if s == "/proc" => Ok(FileStat {
                file_type: FileType::Directory,
                size: 0,
                permissions: FilePermissions::ReadOnly,
                inode_number: 0, //TODO
                filesystem,
            }),
            _ => Err("Cannot stat proc. No such file".to_owned()),
        }
    }

    pub fn list_dir(&self, path: &Path) -> Result<Vec<String>> {
        match path.as_str() {
            s if s == "/proc" => Ok(vec!["/proc/status".to_owned()]),
            _ => Err("Cannot list this proc file/dir".to_owned()),
        }
    }
}
