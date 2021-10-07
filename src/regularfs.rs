use std::collections::hash_map;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::MutexGuard;

use crate::sys::{GlobalProcessTable, IoctlRequest, GLOBAL_PROCESS_TABLE};
use crate::util::{
    DirectoryEntry, Ecode, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, SysResult, Uid,
};
use crate::vfs::Filesystem;

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
            permissions: FilePermissions::new(7, 5),
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

    fn create_inode(
        &mut self,
        file_type: FileType,
        permissions: FilePermissions,
        parent_id: InodeIdentifier,
    ) -> Ino {
        let mut processes = lock_global_process_table();
        let user_id = processes.current().uid;

        let inode_number = self.next_inode_number;
        self.next_inode_number += 1;
        let inode = Inode {
            parent_id,
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

        inode_number
    }

    fn remove_inode(&mut self, inode_number: Ino) -> SysResult<()> {
        //TODO remove directory / regular file
        //TODO if someone has an open file, don't delete it in such a way that
        // read/writes start failing for that process

        match self.inodes.entry(inode_number) {
            hash_map::Entry::Occupied(e) => {
                let mut processes = lock_global_process_table();
                let uid = processes.current().uid;
                let inode = e.get();
                let is_owner = uid == inode.user_id;
                let permissions = inode.permissions;

                // TODO is this correct? It should be the parent directory's permissions
                // that determines if we can remove this file?
                let allowed = (is_owner && permissions.owner_write()) || permissions.others_write();
                if allowed {
                    e.remove();
                    Ok(())
                } else {
                    Err(Ecode::Custom("Not allowed".to_owned()))
                }
            }
            hash_map::Entry::Vacant(_) => Err(Ecode::Enoent),
        }
    }

    fn directory_mut(&mut self, inode_number: Ino) -> SysResult<&mut Directory> {
        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err(Ecode::Enotdir),
            None => Err(Ecode::Enoent),
        }
    }

    fn directory(&self, inode_number: Ino) -> SysResult<&Directory> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err(Ecode::Enotdir),
            None => Err(Ecode::Enoent),
        }
    }

    fn add_child_to_directory(
        &mut self,
        dir_inode_number: Ino,
        name: String,
        child_inode_id: InodeIdentifier,
    ) -> SysResult<()> {
        let dir = self.directory_mut(dir_inode_number)?;
        dir.insert(name, child_inode_id);
        Ok(())
    }

    fn remove_child_from_directory(
        &mut self,
        dir_inode_number: Ino,
        child_inode_id: InodeIdentifier,
    ) -> SysResult<()> {
        let dir = self.directory_mut(dir_inode_number)?;
        dir.retain(|_name, child_id| *child_id != child_inode_id);
        Ok(())
    }

    fn update_inode_parent(&mut self, inode_number: Ino, new_parent_id: InodeIdentifier) -> bool {
        if let Some(mut inode) = self.inode_mut(inode_number) {
            inode.parent_id = new_parent_id;
            return true;
        }
        false
    }

    fn list_directory(&mut self, inode_number: Ino) -> SysResult<Vec<DirectoryEntry>> {
        let dir = self.directory(inode_number)?;
        let listing = dir
            .iter()
            .map(|(name, id)| DirectoryEntry {
                inode_id: *id,
                name: name.clone(),
            })
            .collect();
        Ok(listing)
    }

    fn open_file(&mut self, inode_number: Ino, id: OpenFileId) -> SysResult<()> {
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

    fn close_file(&mut self, id: OpenFileId) -> SysResult<()> {
        for file in self.files.values_mut() {
            file.open_ids.retain(|open_id| *open_id != id);
        }

        eprintln!("Closed id {:?}", id);
        Ok(())
    }

    fn read_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &mut [u8],
        file_offset: usize,
    ) -> SysResult<Option<usize>> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Regular(regular_file)) => {
                let mut cursor = Cursor::new(&regular_file);
                cursor.set_position(file_offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(Some(num_read))
            }
            Some(FileContent::Dir(_)) => Err(Ecode::Eisdir),
            None => Err(Ecode::Custom("No such file".to_owned())),
        }
    }

    fn write_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        mut file_offset: usize,
    ) -> SysResult<usize> {
        //TODO permissions

        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Regular(f)) => {
                let mut num_written = 0;
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
            // TODO: We shouldn't even get here? Can you open a directory for reading?
            Some(FileContent::Dir(_)) => Err(Ecode::Custom("It's a directory".to_owned())),
            None => Err(Ecode::Custom("No such file".to_owned())),
        }
    }

    fn inode_mut(&mut self, inode_number: Ino) -> Option<&mut Inode> {
        self.inodes.get_mut(&inode_number)
    }

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
        self.inodes.get(&inode_number).copied()
    }
}

impl Filesystem for RegularFilesystem {
    fn root_inode_id(&self) -> InodeIdentifier {
        InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: ROOT_INODE_NUMBER,
        }
    }

    fn ioctl(&mut self, _inode_number: Ino, _req: IoctlRequest) -> SysResult<()> {
        Err(Ecode::Enotty)
    }

    fn create(
        &mut self,
        parent_directory: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> SysResult<Ino> {
        Ok(self.create_inode(file_type, permissions, parent_directory))
    }

    fn truncate(&mut self, inode_number: Ino) -> SysResult<()> {
        let file = self.files.get_mut(&inode_number).ok_or(Ecode::Enoent)?;
        match &mut file.content {
            FileContent::Regular(regular_file) => {
                regular_file.clear();
                Ok(())
            }
            FileContent::Dir(_) => Err(Ecode::Custom("Can't truncate directory".to_owned())),
        }
    }

    fn remove(&mut self, inode_number: Ino) -> SysResult<()> {
        self.remove_inode(inode_number)
    }

    fn inode(&self, inode_number: Ino) -> Option<Inode> {
        self.inode(inode_number)
    }

    fn add_directory_entry(
        &mut self,
        directory: Ino,
        name: String,
        child: InodeIdentifier,
    ) -> SysResult<()> {
        self.add_child_to_directory(directory, name, child)
    }

    fn remove_directory_entry(&mut self, directory: Ino, child: InodeIdentifier) -> SysResult<()> {
        self.remove_child_from_directory(directory, child)
    }

    fn directory_entries(&mut self, directory: Ino) -> SysResult<Vec<DirectoryEntry>> {
        self.list_directory(directory)
    }

    fn update_inode_parent(&mut self, inode_number: Ino, new_parent: InodeIdentifier) -> bool {
        self.update_inode_parent(inode_number, new_parent)
    }

    fn open(&mut self, inode_number: Ino, id: OpenFileId) -> SysResult<()> {
        self.open_file(inode_number, id)
    }

    fn close(&mut self, id: OpenFileId) -> SysResult<()> {
        self.close_file(id)
    }

    fn read(
        &mut self,
        inode_number: Ino,
        _id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> SysResult<Option<usize>> {
        self.read_file_at_offset(inode_number, buf, file_offset)
    }

    fn write(&mut self, inode_number: Ino, buf: &[u8], file_offset: usize) -> SysResult<usize> {
        self.write_file_at_offset(inode_number, buf, file_offset)
    }
}
