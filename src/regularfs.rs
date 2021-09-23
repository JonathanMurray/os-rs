use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::util::{
    DirectoryEntry, FilePermissions, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId,
};
use crate::vfs::Filesystem;

type Result<T> = core::result::Result<T, String>;

type Directory = HashMap<String, InodeIdentifier>;
type RegularFile = Vec<u8>;

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
            permissions: FilePermissions::ReadOnly,
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
        };
        self.inodes.insert(inode_number, inode);
        self.files.insert(inode_number, File::new(file_type));

        inode_number
    }

    fn remove_inode(&mut self, inode_number: Ino) -> Result<()> {
        //TODO remove directory / regular file
        //TODO if someone has an open file, don't delete it in such a way that
        // read/writes start failing for that process
        self.inodes.remove(&inode_number);
        Ok(())
    }

    fn directory_mut(&mut self, inode_number: Ino) -> Result<&mut Directory> {
        match self
            .files
            .get_mut(&inode_number)
            .map(|file| &mut file.content)
        {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err(format!("Not a directory: {}", inode_number)),
            None => Err(format!("No file with inode number: {}", inode_number)),
        }
    }

    fn directory(&self, inode_number: Ino) -> Result<&Directory> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Dir(dir)) => Ok(dir),
            Some(FileContent::Regular(_)) => Err(format!("Not a directory: {}", inode_number)),
            None => Err(format!("No file with inode number: {}", inode_number)),
        }
    }

    fn add_child_to_directory(
        &mut self,
        dir_inode_number: Ino,
        name: String,
        child_inode_id: InodeIdentifier,
    ) -> Result<()> {
        let dir = self.directory_mut(dir_inode_number)?;
        dir.insert(name, child_inode_id);
        Ok(())
    }

    fn remove_child_from_directory(
        &mut self,
        dir_inode_number: Ino,
        child_inode_id: InodeIdentifier,
    ) -> Result<()> {
        let dir = self.directory_mut(dir_inode_number)?;
        dir.retain(|_name, child_id| *child_id != child_inode_id);
        Ok(())
    }

    fn set_inode_parent(
        &mut self,
        inode_number: Ino,
        new_parent_id: InodeIdentifier,
    ) -> Result<()> {
        self.inode_mut(inode_number)?.parent_id = new_parent_id;
        Ok(())
    }

    fn list_directory(&mut self, inode_number: Ino) -> Result<Vec<DirectoryEntry>> {
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

    fn open_file(&mut self, inode_number: Ino, id: OpenFileId) -> Result<()> {
        let file = self
            .files
            .get_mut(&inode_number)
            .ok_or_else(|| "No such file".to_owned())?;

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

    fn close_file(&mut self, id: OpenFileId) -> Result<()> {
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
    ) -> Result<usize> {
        match self.files.get(&inode_number).map(|file| &file.content) {
            Some(FileContent::Regular(regular_file)) => {
                let mut cursor = Cursor::new(&regular_file);
                cursor.set_position(file_offset as u64);
                let num_read = cursor.read(buf).expect("Failed to read from file");
                Ok(num_read)
            }
            Some(FileContent::Dir(_)) => Err("It's a directory".to_owned()),
            None => Err("No such file".to_owned()),
        }
    }

    fn write_file_at_offset(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        mut file_offset: usize,
    ) -> Result<usize> {
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
            Some(FileContent::Dir(_)) => Err("It's a directory".to_owned()),
            None => Err("No such file".to_owned()),
        }
    }

    fn inode_mut(&mut self, inode_number: Ino) -> Result<&mut Inode> {
        self.inodes
            .get_mut(&inode_number)
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }

    fn inode(&self, inode_number: Ino) -> Result<Inode> {
        self.inodes
            .get(&inode_number)
            .copied()
            .ok_or_else(|| format!("No inode with number: {}", inode_number))
    }
}

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
        Ok(self.create_inode(file_type, permissions, parent_directory))
    }

    fn remove(&mut self, inode_number: Ino) -> Result<()> {
        self.remove_inode(inode_number)
    }

    fn inode(&self, inode_number: Ino) -> Result<Inode> {
        self.inode(inode_number)
    }

    fn add_directory_entry(
        &mut self,
        directory: Ino,
        name: String,
        child: InodeIdentifier,
    ) -> Result<()> {
        self.add_child_to_directory(directory, name, child)
    }

    fn remove_directory_entry(&mut self, directory: Ino, child: InodeIdentifier) -> Result<()> {
        self.remove_child_from_directory(directory, child)
    }

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>> {
        self.list_directory(directory)
    }

    fn update_inode_parent(
        &mut self,
        inode_number: Ino,
        new_parent: InodeIdentifier,
    ) -> Result<()> {
        self.set_inode_parent(inode_number, new_parent)
    }

    fn open(&mut self, inode_number: Ino, id: OpenFileId) -> Result<()> {
        self.open_file(inode_number, id)
    }

    fn close(&mut self, id: OpenFileId) -> Result<()> {
        self.close_file(id)
    }

    fn read(
        &mut self,
        inode_number: Ino,
        _id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        self.read_file_at_offset(inode_number, buf, file_offset)
    }

    fn write(&mut self, inode_number: Ino, buf: &[u8], file_offset: usize) -> Result<usize> {
        self.write_file_at_offset(inode_number, buf, file_offset)
    }
}
