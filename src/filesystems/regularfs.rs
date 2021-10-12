use std::collections::hash_map;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::MutexGuard;

use crate::filesystems::{AccessMode, Filesystem, WriteError};
use crate::sys::{GlobalProcessTable, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, Ecode, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Uid,
};

type Directory = HashMap<String, InodeIdentifier>;
type RegularFile = Vec<u8>;

fn lock_global_process_table() -> MutexGuard<'static, GlobalProcessTable> {
    // LOCKING: VFS must never be accessed while holding this lock
    GLOBAL_PROCESS_TABLE.lock().unwrap()
}

#[derive(Debug)]
enum FileContent {
    Dir(Directory),
    Regular(RegularFile),
}

#[derive(Debug)]
struct File {
    content: FileContent,
    open_ids: Vec<OpenFileId>,
}

impl File {
    fn new(file_type: FileType) -> Self {
        match file_type {
            FileType::Directory => Self {
                content: FileContent::Dir(Default::default()),
                open_ids: Default::default(),
            },
            FileType::Regular => Self {
                content: FileContent::Regular(Default::default()),
                open_ids: Default::default(),
            },
            FileType::CharacterDevice => panic!("Cannot create character device on regular fs"),
            FileType::Pipe => panic!("Cannot create pipe on regular fs"),
        }
    }
}

#[derive(Debug)]
pub struct RegularFilesystem {
    inodes: HashMap<Ino, Inode>,
    next_inode_number: Ino,
    files: HashMap<Ino, File>,
}

const ROOT_INODE_NUMBER: u32 = 0;

impl RegularFilesystem {
    pub fn new() -> Self {
        let root_inode_id = InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: ROOT_INODE_NUMBER,
        };
        let root_inode = Inode {
            parent_id: root_inode_id, //root has self as parent
            id: root_inode_id,
            file_type: FileType::Directory,
            size: 0,
            permissions: FilePermissions::new(7, 7),
            user_id: Uid(0),
        };

        let next_inode_number = root_inode.id.number + 1;
        let mut files = HashMap::new();
        files.insert(
            root_inode.id.number,
            File {
                content: FileContent::Dir(Default::default()),
                open_ids: Default::default(),
            },
        );
        let mut inodes = HashMap::new();
        inodes.insert(root_inode.id.number, root_inode);
        Self {
            inodes,
            next_inode_number,
            files,
        }
    }

    fn dir_mut(&mut self, inode_number: Ino) -> Result<&mut Directory> {
        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err("not a directory".to_owned()),
            None => Err("No such inode".to_owned()),
        }
    }

    fn dir(&self, inode_number: Ino) -> Result<&Directory> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err("not a directory".to_owned()),
            None => Err("No such inode".to_owned()),
        }
    }

    fn inode_mut(&mut self, inode_number: Ino) -> Option<&mut Inode> {
        self.inodes.get_mut(&inode_number)
    }
}

type Result<T> = std::result::Result<T, String>;

impl Filesystem for RegularFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: ROOT_INODE_NUMBER,
        }
    }

    fn create(
        &mut self,
        parent_directory: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<Ino> {
        let mut processes = lock_global_process_table();
        let user_id = processes.current().uid;

        let inode_number = self.next_inode_number;
        self.next_inode_number += 1;
        let inode = Inode {
            parent_id: parent_directory,
            id: InodeIdentifier {
                filesystem_id: FilesystemId::Main,
                number: inode_number,
            },
            file_type,
            size: 0,
            permissions,
            user_id,
        };
        self.inodes.insert(inode_number, inode);
        self.files.insert(inode_number, File::new(file_type));

        Ok(inode_number)
    }

    fn truncate(&mut self, inode_number: Ino) -> Result<()> {
        let file = self.files.get_mut(&inode_number).unwrap();
        match &mut file.content {
            FileContent::Regular(regular_file) => {
                regular_file.clear();
                Ok(())
            }
            FileContent::Dir(_) => Err("Cannot truncate dir".to_owned()),
        }
    }

    fn remove(&mut self, inode_number: Ino) -> Result<()> {
        //TODO remove directory / regular file
        //TODO if someone has an open file, don't delete it in such a way that
        // read/writes start failing for that process

        match self.inodes.entry(inode_number) {
            hash_map::Entry::Occupied(e) => {
                e.remove();
                Ok(())
            }
            hash_map::Entry::Vacant(_) => Err("no such inode".to_owned()),
        }
    }

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
        self.inodes.get(&inode_number).copied()
    }

    fn add_directory_entry(
        &mut self,
        directory: Ino,
        name: String,
        child: InodeIdentifier,
    ) -> Result<()> {
        let dir = self.dir_mut(directory)?;
        dir.insert(name, child);
        Ok(())
    }

    fn remove_directory_entry(&mut self, directory: Ino, child: InodeIdentifier) -> Result<()> {
        let dir = self.dir_mut(directory)?;
        dir.retain(|_name, child_id| *child_id != child);
        Ok(())
    }

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>> {
        let dir = self.dir(directory)?;
        let listing = dir
            .iter()
            .map(|(name, id)| DirectoryEntry {
                inode_id: *id,
                name: name.clone(),
            })
            .collect();
        Ok(listing)
    }

    fn update_inode_parent(&mut self, inode_number: Ino, new_parent: InodeIdentifier) -> bool {
        if let Some(mut inode) = self.inode_mut(inode_number) {
            inode.parent_id = new_parent;
            return true;
        }
        false
    }

    fn open(&mut self, inode_number: Ino, id: OpenFileId, _access_mode: AccessMode) -> Result<()> {
        let file = self.files.get_mut(&inode_number).ok_or(Ecode::Enoent)?;

        assert!(
            !file.open_ids.contains(&id),
            "{} is already opened with id {:?}",
            inode_number,
            id
        );
        file.open_ids.push(id);
        eprintln!("Opened inode {} with id {:?}", inode_number, id);
        Ok(())
    }

    fn close(&mut self, id: OpenFileId) {
        for file in self.files.values_mut() {
            file.open_ids.retain(|open_id| *open_id != id);
        }

        eprintln!("Closed id {:?}", id);
    }

    fn read(
        &mut self,
        inode_number: Ino,
        _id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Regular(regular_file)) => {
                let mut cursor = Cursor::new(&regular_file);
                cursor.set_position(file_offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(Some(num_read))
            }
            Some(FileContent::Dir(_)) => Err("Is directory".to_owned()),
            None => Err("No such file".to_owned()),
        }
    }

    fn write(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        file_offset: usize,
    ) -> std::result::Result<usize, WriteError> {
        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Regular(f)) => {
                let mut num_written = 0;
                let mut file_offset = file_offset;
                for &b in buf {
                    if file_offset < f.len() {
                        f[file_offset] = b;
                    } else {
                        f.push(b);
                    }
                    file_offset += 1;
                    num_written += 1;
                }

                self.inode_mut(inode_number)
                    .expect("Inode must exist at write")
                    .size = f.len();

                Ok(num_written)
            }
            Some(FileContent::Dir(_)) => Err(WriteError::Unexpected("Is directory".to_owned())),
            None => Err(WriteError::Unexpected("No such file".to_owned())),
        }
    }
}
