use crate::devfs::DevFilesystem;
use crate::procfs::ProcFilesystem;
use crate::regularfs::RegularFilesystem;
use crate::util::{
    DirectoryEntry, FilePermissions, FileStat, FileType, FilesystemId, Ino, Inode, InodeIdentifier,
    OpenFileId, Pid,
};
use std::collections::{hash_map::Entry, HashMap};

type Result<T> = core::result::Result<T, String>;

pub trait Filesystem: std::fmt::Debug + Send {
    fn root_inode_id(&self) -> InodeIdentifier;

    fn create(
        &mut self,
        parent_directory: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<Ino>;

    fn remove(&mut self, inode_number: Ino) -> Result<()>;

    fn inode(&self, inode_number: Ino) -> Result<Inode>;

    fn add_directory_entry(
        &mut self,
        directory: Ino,
        name: String,
        child: InodeIdentifier,
    ) -> Result<()>;

    fn remove_directory_entry(&mut self, directory: Ino, child: InodeIdentifier) -> Result<()>;

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>>;

    fn update_inode_parent(&mut self, inode_number: Ino, new_parent: InodeIdentifier)
        -> Result<()>;

    fn open(&mut self, inode_number: Ino, id: OpenFileId) -> Result<()>;

    fn close(&mut self, id: OpenFileId) -> Result<()>;

    fn read(
        &mut self,
        inode_number: Ino,
        id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<usize>;

    fn write(&mut self, inode_number: Ino, buf: &[u8], file_offset: usize) -> Result<usize>;
}

#[derive(Debug)]
struct OpenFile {
    inode_id: InodeIdentifier,
    offset: usize,
    owner: Pid,
}

#[derive(Debug)]
pub struct VirtualFilesystemSwitch {
    fs: HashMap<FilesystemId, Box<dyn Filesystem>>,
    next_open_file_id: OpenFileId,
    open_files: HashMap<OpenFileId, OpenFile>,
}

impl VirtualFilesystemSwitch {
    pub fn new() -> Self {
        let mut mainfs = RegularFilesystem::new();
        let root_inode_id = mainfs.root_inode_id();
        let procfs = ProcFilesystem::new(root_inode_id);
        let devfs = DevFilesystem::new(root_inode_id);
        mainfs
            .add_directory_entry(
                root_inode_id.number,
                "proc".to_owned(),
                procfs.root_inode_id(),
            )
            .expect("Add proc to root dir");
        mainfs
            .add_directory_entry(
                root_inode_id.number,
                "dev".to_owned(),
                devfs.root_inode_id(),
            )
            .expect("Add dev to root dir");

        let mut fs: HashMap<FilesystemId, Box<dyn Filesystem>> = HashMap::new();
        fs.insert(FilesystemId::Main, Box::new(mainfs));
        fs.insert(FilesystemId::Proc, Box::new(procfs));
        fs.insert(FilesystemId::Dev, Box::new(devfs));

        Self {
            fs,
            next_open_file_id: OpenFileId(0),
            open_files: Default::default(),
        }
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

        let fs = self.fs.get_mut(&filesystem_id).unwrap();
        let new_ino = fs.create(parent_inode_id, file_type, permissions)?;
        fs.add_directory_entry(
            parent_inode_id.number,
            name,
            InodeIdentifier {
                filesystem_id,
                number: new_ino,
            },
        )?;
        Ok(())
    }

    pub fn unlink_file(&mut self, path: &str, cwd: InodeIdentifier) -> Result<()> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        let inode_id = inode.id;

        if inode.file_type == FileType::Directory {
            return Err("Cannot remove directory".to_owned());
        }
        let parent_id = inode.parent_id;

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        fs.remove(inode_id.number)?;
        let fs = self.fs.get_mut(&parent_id.filesystem_id).unwrap();
        fs.remove_directory_entry(parent_id.number, inode_id)
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

        //HACK: Assume everything is on same fs
        let fs = self.fs.get_mut(&old_parent_inode.id.filesystem_id).unwrap();

        fs.update_inode_parent(inode_id.number, new_parent_id)?;
        fs.remove_directory_entry(old_parent_id.number, inode_id)?;
        fs.add_directory_entry(new_parent_id.number, new_base_name, inode_id)
    }

    pub fn stat_file(&mut self, path: &str, cwd: InodeIdentifier) -> Result<FileStat> {
        //TODO make cwd optional
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

    pub fn list_dir(&mut self, open_file_id: OpenFileId) -> Result<Vec<DirectoryEntry>> {
        let inode_id = self
            .open_files
            .get(&open_file_id)
            .ok_or("No such open file")?
            .inode_id;
        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        fs.directory_entries(inode_id.number)
    }

    pub fn open_file(&mut self, path: &str, cwd: InodeIdentifier, pid: Pid) -> Result<OpenFileId> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd)?;
        let inode_id = inode.id;

        let open_file_id = self.next_open_file_id;
        self.open_files.insert(
            open_file_id,
            OpenFile {
                inode_id,
                offset: 0,
                owner: pid,
            },
        );
        self.next_open_file_id = OpenFileId(self.next_open_file_id.0 + 1);

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();

        //TODO do we need to delegate this, or is it enough that the
        //VFS keeps track of open files?
        fs.open(inode_id.number, open_file_id)?;
        Ok(open_file_id)
    }

    pub fn close_file(&mut self, id: OpenFileId, pid: Pid) -> Result<()> {
        match self.open_files.entry(id) {
            Entry::Occupied(e) => {
                let open_file = e.get();
                if open_file.owner == pid {
                    let fs = self.fs.get_mut(&open_file.inode_id.filesystem_id).unwrap();
                    e.remove();
                    fs.close(id)
                } else {
                    Ok(())
                }
            }
            Entry::Vacant(_) => Err("No such open file".to_owned()),
        }
    }

    fn get_open_file_mut(&mut self, id: OpenFileId) -> Result<&mut OpenFile> {
        self.open_files
            .get_mut(&id)
            .ok_or(format!("No open file found for id: {:?}", id))
    }

    pub fn read_file(&mut self, open_file_id: OpenFileId, buf: &mut [u8]) -> Result<usize> {
        let (inode_id, offset) = {
            let open_file = self.get_open_file_mut(open_file_id)?;
            (open_file.inode_id, open_file.offset)
        };

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        let n_read = fs.read(inode_id.number, open_file_id, buf, offset)?;

        let open_file = self.get_open_file_mut(open_file_id)?;
        open_file.offset += n_read;
        Ok(n_read)
    }

    pub fn write_file(&mut self, open_file_id: OpenFileId, buf: &[u8]) -> Result<usize> {
        let (inode_id, offset) = {
            let open_file = self.get_open_file_mut(open_file_id)?;
            (open_file.inode_id, open_file.offset)
        };

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        let n_read = fs.write(inode_id.number, buf, offset)?;

        let open_file = self.get_open_file_mut(open_file_id)?;
        open_file.offset += n_read;
        Ok(n_read)
    }

    pub fn seek(&mut self, open_file_id: OpenFileId, offset: usize) -> Result<()> {
        self.get_open_file_mut(open_file_id)?.offset = offset;
        Ok(())
    }

    pub fn path_from_inode(&mut self, inode_id: InodeIdentifier) -> Result<String> {
        let mut parts_reverse: Vec<String> = Vec::new();
        let mut inode = self.inode(inode_id)?;

        loop {
            if inode.parent_id == inode.id {
                // The root inode has itself as a parent
                break;
            }

            let parent_inode = self.inode(inode.parent_id)?;
            let fs = self.fs.get_mut(&inode.parent_id.filesystem_id).unwrap();
            let name = fs
                .directory_entries(inode.parent_id.number)?
                .into_iter()
                .find(|entry| entry.inode_id == inode.id)
                .ok_or_else(|| "no such inode".to_owned())?
                .name;
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
        //TODO Make cwd optional. Should be possible to call this with absolute paths w/o cwd
        let mut inode = match parts.get(0) {
            Some(&"") => {
                // (empty string here means the path starts with '/', since we split on it)
                // We got an absolute path. Start from root.
                parts = &parts[1..];

                let fs = self.fs.get(&FilesystemId::Main).unwrap();
                let root_inode_number = fs.root_inode_id().number;
                fs.inode(root_inode_number)
                    .expect("Must have root inode with number 0")
            }
            None => self.inode(cwd)?,    // resolving a file in cwd
            Some(_) => self.inode(cwd)?, // resolving something further down in the tree
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
                _ => {
                    self.fs
                        .get_mut(&inode.id.filesystem_id)
                        .unwrap()
                        .directory_entries(inode_id.number)?
                        .into_iter()
                        .find(|entry| entry.name == **part)
                        .ok_or_else(|| "no such inode".to_owned())?
                        .inode_id
                }
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
        let fs = self.fs.get(&inode_id.filesystem_id).unwrap();
        fs.inode(inode_id.number)
    }
}
