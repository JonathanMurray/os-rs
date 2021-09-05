use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::sys::{FilePermissions, FileStat, FileType, Path, Processes, _Process};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct ProcFilesystem {
    startup_time: Instant,
    // shared between system and procfs.
    processes: Arc<Mutex<Processes>>,
    file_contents: HashMap<(u32, u32), String>,
}

impl ProcFilesystem {
    pub fn new(processes: Arc<Mutex<Processes>>) -> Self {
        Self {
            startup_time: Instant::now(),
            processes,
            file_contents: HashMap::new(),
        }
    }

    pub fn open_file(&mut self, path: &Path, current_proc: &_Process, fd: u32) -> Result<u32> {
        match path.as_str() {
            s if s == "/proc/status" => {
                let content = self._status_file_content(current_proc);
                self.file_contents.insert((current_proc.pid, fd), content);
                let inode = 0;
                Ok(inode)
            }
            s if s == "/proc" => Err("Cannot open. Is directory".to_owned()),
            _ => Err("Cannot open. No such file".to_owned()),
        }
    }

    pub fn close_file(&mut self, current_pid: u32, fd: u32) -> Result<()> {
        self.file_contents
            .remove(&(current_pid, fd))
            .map(|_| ())
            .ok_or("No such open file".to_owned())
    }

    pub fn read_file_at_offset(
        &mut self,
        current_proc: &_Process,
        fd: u32,
        inode_number: u32,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match inode_number {
            0 => {
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

    fn _status_file_content(&self, current_proc: &_Process) -> String {
        let mut content = String::new();
        let uptime = Instant::now().duration_since(self.startup_time);
        content.push_str(&format!("uptime: {:.2}\n", uptime.as_secs_f32()));
        let processes = &self
            .processes
            .lock()
            .expect("Accessing processes from procfs");
        content.push_str(&format!("{} processes:\n", processes.len()));
        for (pid, proc) in processes.iter() {
            if &current_proc.pid == pid {
                content.push_str(&format!("* {}: {}\n", current_proc.pid, current_proc.name));
                content.push_str(&format!("    open files: {:?}\n", current_proc.open_files));

                content.push_str(&format!("     log: {:?}\n", current_proc.log));
            } else {
                let proc = proc.lock().expect("Accessing proc from procfs");
                content.push_str(&format!("  {}: {}\n", pid, proc.name));
                content.push_str(&format!("    open files: {:?}\n", proc.open_files));
                content.push_str(&format!("     log: {:?}\n", proc.log));
            };
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
