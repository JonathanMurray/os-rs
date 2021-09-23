use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};
use std::sync::MutexGuard;
use std::time::Instant;

use crate::sys::{GlobalProcessTable, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Pid,
};
use crate::vfs::Filesystem;

type Result<T> = core::result::Result<T, String>;

fn lock_global_process_table() -> MutexGuard<'static, GlobalProcessTable> {
    // LOCKING: VFS must never be accessed while holding this lock
    GLOBAL_PROCESS_TABLE.lock().unwrap()
}

#[derive(Debug)]
pub struct ProcFilesystem {
    parent_inode_id: InodeIdentifier,
    startup_time: Instant,
    //TODO unify handling of files/directories ==> clearer error handling
    file_contents: HashMap<OpenFileId, String>,
    open_directories: HashSet<OpenFileId>,
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

    pub fn root_inode_id(&self) -> InodeIdentifier {
        InodeIdentifier {
            filesystem_id: FilesystemId::Proc,
            number: 0,
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
                        "{} {} {} {:?} {} {:?}\n",
                        proc.pid.0,
                        proc.parent_pid.0,
                        proc.name,
                        proc.state,
                        proc.open_files.len(),
                        proc.open_files
                    );
                    lines.push((proc.pid, line));
                }
                lines.sort_by_key(|pair| pair.0 .0);
                for line in lines.into_iter().map(|pair| pair.1) {
                    content.push_str(&line);
                }
                self.file_contents.insert(open_file_id, content);
                Ok(())
            }
            0 => {
                self.open_directories.insert(open_file_id);
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
                        self.file_contents.insert(open_file_id, content);
                        return Ok(());
                    } else {
                        println!("DEBUG: No process with pid: {:?}", pid);
                    }
                }

                return Err(format!(
                    "Cannot open. No file on procfs with inode number: {}",
                    inode_number
                ));
            }
        }
    }

    pub fn close_file(&mut self, open_file_id: OpenFileId) -> Result<()> {
        let closed_regular_file = self.file_contents.remove(&open_file_id).is_some();
        if !closed_regular_file && !self.open_directories.remove(&open_file_id) {
            return Err(format!("No open file with id: {:?}", open_file_id));
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
                    let pid = Pid(inode_number - 1000);

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
            _ => Err(format!(
                "No directory on procfs with inode number: {}",
                inode_number
            )),
        }
    }

    pub fn read_file_at_offset(
        &mut self,
        open_file_id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        if self.open_directories.contains(&open_file_id) {
            return Err("Cannot read directory".to_owned());
        }
        let content = self
            .file_contents
            .get(&open_file_id)
            .ok_or_else(|| format!("No open file on procfs with id {:?}", open_file_id))?;
        let mut cursor = Cursor::new(&content);
        cursor.set_position(file_offset as u64);
        let num_read = cursor.read(buf).expect("Failed to read from file");
        Ok(num_read)
    }
}

impl Filesystem for ProcFilesystem {
    fn create(
        &mut self,
        _parent_directory: InodeIdentifier,
        _file_type: FileType,
        _permissions: FilePermissions,
    ) -> Result<Ino> {
        Err("Can't create file on procfs".to_owned())
    }

    fn remove(&mut self, _inode_number: Ino) -> Result<()> {
        Err("Can't remove file on procfs".to_owned())
    }

    fn inode(&self, inode_number: Ino) -> Result<Inode> {
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

    fn update_inode_parent(
        &mut self,
        _inode_number: Ino,
        _new_parent: InodeIdentifier,
    ) -> Result<()> {
        panic!("We shouldn't get here? procfs update_inode_parent")
    }

    fn open(&mut self, inode_number: Ino, open_file_id: OpenFileId) -> Result<()> {
        eprintln!("procfs open({}, {:?})", inode_number, open_file_id);
        self.open_file(inode_number, open_file_id)
    }

    fn close(&mut self, id: OpenFileId) -> Result<()> {
        eprintln!("procfs close({:?})", id);
        self.close_file(id)
    }

    fn read(
        &mut self,
        _inode_number: Ino,
        id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        self.read_file_at_offset(id, buf, file_offset)
    }

    fn write(&mut self, _inode_number: Ino, _buf: &[u8], _file_offset: usize) -> Result<usize> {
        Err("Can't write to procfs".to_owned())
    }
}
