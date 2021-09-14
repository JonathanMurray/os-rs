use crate::procfs::ProcFilesystem;
use crate::regularfs::RegularFilesystem;
use crate::util::{
    DirectoryEntry, Fd, FilePermissions, FileStat, FileType, FilesystemId, Inode, InodeIdentifier,
};

type Result<T> = core::result::Result<T, String>;

#[derive(Debug)]
pub struct VirtualFilesystemSwitch {
    fs: RegularFilesystem,
    procfs: ProcFilesystem,
}

impl VirtualFilesystemSwitch {
    pub fn new() -> Self {
        let root_inode_id = InodeIdentifier {
            filesystem_id: FilesystemId::Main,
            number: 0,
        };
        let root_inode = Inode {
            parent_id: root_inode_id, //root has self as parent
            id: root_inode_id,
            file_type: FileType::Directory,
            size: 0,
            permissions: FilePermissions::ReadOnly,
        };
        let mut fs = RegularFilesystem::new(root_inode);
        fs.add_child_to_directory(
            0,
            "proc".to_owned(),
            InodeIdentifier {
                filesystem_id: FilesystemId::Proc,
                number: 0,
            },
        )
        .expect("Add proc to root dir");
        let procfs = ProcFilesystem::new(root_inode_id);
        Self { fs, procfs }
    }

    pub fn create_file<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
        cwd: InodeIdentifier,
        filesystem_id: Option<FilesystemId>,
    ) -> Result<()> {
        let path = path.into();
        let parts: Vec<&str> = path.split('/').collect();
        let parent_inode = self.resolve_from_parts(&parts[..parts.len() - 1], cwd)?;
        let parent_id = parent_inode.id;

        if !parent_inode.is_dir() {
            return Err("Parent is not a directory".to_owned());
        }

        let name = parts[parts.len() - 1].to_owned();

        self._create_file(parent_id, file_type, permissions, filesystem_id, name)
    }

    fn _create_file(
        &mut self,
        parent_inode_id: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
        filesystem_id: Option<FilesystemId>,
        name: String,
    ) -> Result<()> {
        // file can be on different filesystem than its parent, for example /proc
        let filesystem_id = filesystem_id.unwrap_or(parent_inode_id.filesystem_id);

        if filesystem_id == FilesystemId::Main {
            let new_ino = self
                .fs
                .create_inode(file_type, permissions, parent_inode_id);
            self.fs.add_child_to_directory(
                parent_inode_id.number,
                name,
                InodeIdentifier {
                    filesystem_id,
                    number: new_ino,
                },
            )?;
        } else {
            return Err("Can't create inode on procfs".to_owned());
        };

        Ok(())
    }

    pub fn remove_file(&mut self, path: &str, cwd: InodeIdentifier) -> Result<()> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        let inode_id = inode.id;

        let inode = self.inode(inode_id)?;

        if inode.file_type == FileType::Directory {
            return Err("Cannot remove directory".to_owned());
        }
        let parent_id = inode.parent_id;

        match inode_id.filesystem_id {
            FilesystemId::Main => {
                self.fs.remove_inode(inode_id);
                self.fs
                    .remove_child_from_directory(parent_id.number, inode_id)
            }
            FilesystemId::Proc => Err("Can't remove file from procfs".to_owned()),
        }
    }

    pub fn rename_file<S: Into<String>>(
        &mut self,
        old_path: &str,
        new_path: S,
        cwd: InodeIdentifier,
    ) -> Result<()> {
        //TODO: handle replacing existing file
        let new_path = new_path.into();

        let old_parts: Vec<&str> = old_path.split('/').collect();
        let inode = self.resolve_from_parts(&old_parts, cwd)?;
        let inode_id = inode.id;
        let old_parent_id = inode.parent_id;

        if inode.file_type == FileType::Directory {
            return Err("Cannot move directory".to_owned());
        }

        let new_parts: Vec<&str> = new_path.split('/').collect();
        let new_base_name = new_parts[new_parts.len() - 1].to_owned();
        let new_parent_inode = self.resolve_from_parts(&new_parts[..new_parts.len() - 1], cwd)?;
        if new_parent_inode.id.filesystem_id != inode_id.filesystem_id {
            // To support this we'd need to create a new inode and copy the file contents
            return Err("Cannot move files between different filesystems".to_owned());
        }
        let new_parent_id = new_parent_inode.id;

        if new_parent_inode.file_type != FileType::Directory {
            return Err("New parent is not a directory".to_owned());
        }

        let old_parent_inode = self.inode(old_parent_id)?;
        if old_parent_inode.id.filesystem_id == FilesystemId::Proc {
            return Err("Cannot move file in procfs".to_owned());
        }
        assert!(old_parent_inode.is_dir());

        //TODO Maybe this should be: fs.rename(old_parent_id, inode_id, new_parent_id, new_name)
        self.fs.set_inode_parent(inode_id.number, new_parent_id)?;
        self.fs
            .remove_child_from_directory(old_parent_id.number, inode_id)?;
        self.fs
            .add_child_to_directory(new_parent_id.number, new_base_name, inode_id)
    }

    pub fn stat_file(&mut self, path: &str, cwd: InodeIdentifier) -> Result<FileStat> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;

        let permissions = inode.permissions;

        Ok(FileStat {
            file_type: inode.file_type,
            size: inode.size,
            permissions,
            inode_id: inode.id,
        })
    }

    pub fn list_dir(&mut self, inode_id: InodeIdentifier) -> Result<Vec<DirectoryEntry>> {
        match inode_id.filesystem_id {
            FilesystemId::Main => self.fs.list_directory(inode_id.number),
            FilesystemId::Proc => self.procfs.list_directory(inode_id.number),
        }
    }

    pub fn open_file(
        &mut self,
        path: &str,
        cwd: InodeIdentifier,
        fd: Fd,
    ) -> Result<InodeIdentifier> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        let inode_id = inode.id;

        match inode_id.filesystem_id {
            FilesystemId::Main => {
                // Nothing needs to be done here
            }
            FilesystemId::Proc => {
                self.procfs.open_file(inode_id.number, fd)?;
            }
        }
        Ok(inode_id)
    }

    pub fn close_file(&mut self, filesystem: FilesystemId, fd: Fd) -> Result<()> {
        match filesystem {
            FilesystemId::Main => {
                // Nothing needs to be done here
                Ok(())
            }
            FilesystemId::Proc => self.procfs.close_file(fd),
        }
    }

    pub fn read_file_at_offset(
        &mut self,
        fd: Fd,
        inode_id: InodeIdentifier,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize> {
        match inode_id.filesystem_id {
            FilesystemId::Proc => self.procfs.read_file_at_offset(fd, buf, file_offset),
            FilesystemId::Main => self
                .fs
                .read_file_at_offset(inode_id.number, buf, file_offset),
        }
    }

    pub fn write_file_at_offset(
        &mut self,
        inode_id: InodeIdentifier,
        buf: &[u8],
        file_offset: usize,
    ) -> Result<usize> {
        if inode_id.filesystem_id == FilesystemId::Proc {
            Err("Can't write to procfs".to_owned())
        } else {
            self.fs
                .write_file_at_offset(inode_id.number, buf, file_offset)
        }
    }

    pub fn path_from_inode(&mut self, inode_id: InodeIdentifier) -> Result<String> {
        let mut parts_reverse = Vec::new();
        let mut inode = self.inode(inode_id)?;

        loop {
            if inode.parent_id == inode.id {
                // The root inode has itself as a parent
                break;
            }

            let parent_inode = self.inode(inode.parent_id)?;
            let name = match inode.parent_id.filesystem_id {
                FilesystemId::Main => self
                    .fs
                    .directory_child_name(inode.parent_id.number, inode.id)?,
                FilesystemId::Proc => todo!("procfs.directory_child_name()"),
            };
            parts_reverse.push(name);

            inode = parent_inode;
        }

        let mut path = String::new();
        for part in parts_reverse.into_iter().rev() {
            path.push('/');
            path.push_str(&part);
        }

        Ok(path)
    }

    fn resolve_from_parts(&mut self, mut parts: &[&str], cwd: InodeIdentifier) -> Result<Inode> {
        let mut inode = match parts.get(0) {
            Some(&"") => {
                // (empty string here means the path starts with '/', since we split on it)
                // We got an absolute path. Start from root.
                parts = &parts[1..];
                // TODO: better way for getting the root inode
                self.fs
                    .inode(0)
                    .expect("Must have root inode with number 0")
            }
            None => self.inode(cwd)?,    // creating a file in cwd
            Some(_) => self.inode(cwd)?, // creating further down
        };

        for part in parts {
            let inode_id = inode.id;

            let next_id = match *part {
                "." => {
                    continue;
                }
                "" => {
                    // Last part can be "" either if path is "/" or if path ends with a trailing slash.
                    // We choose to allow trailing slash to make things easy for now.
                    continue;
                }
                ".." => inode.parent_id,
                _ => match inode.id.filesystem_id {
                    FilesystemId::Main => self.fs.directory_child_id(inode_id.number, part)?,
                    FilesystemId::Proc => self.procfs.directory_child_id(inode_id.number, part)?,
                },
            };

            inode = self.inode(next_id)?;
        }

        let inode_id = inode.id;
        self.inode(inode_id)
    }

    pub fn resolve_directory(&mut self, path: &str, cwd: InodeIdentifier) -> Result<Inode> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        if inode.file_type != FileType::Directory {
            return Err(format!("Not a directory: {}", path));
        }
        Ok(inode)
    }

    fn inode(&self, inode_id: InodeIdentifier) -> Result<Inode> {
        match inode_id.filesystem_id {
            FilesystemId::Main => self.fs.inode(inode_id.number),
            FilesystemId::Proc => self.procfs.inode(inode_id.number),
        }
    }
}
