use crate::pipefs::PipeFilesystem;
use crate::procfs::ProcFilesystem;
use crate::regularfs::RegularFilesystem;
use crate::sys::{
    GlobalProcessTable, IoctlRequest, OpenFlags, Process, SeekOffset, GLOBAL_PROCESS_TABLE,
};
use crate::util::{
    DirectoryEntry, Ecode, FilePermissions, FileStat, FileType, FilesystemId, Ino, Inode,
    InodeIdentifier, OpenFileId, SysResult,
};
use std::collections::HashMap;
use std::sync::{Arc, MutexGuard, Weak};

fn lock_global_process_table() -> MutexGuard<'static, GlobalProcessTable> {
    // LOCKING: VFS must never be accessed while holding this lock
    GLOBAL_PROCESS_TABLE.lock().unwrap()
}

type Result<T> = core::result::Result<T, String>;

#[derive(Debug, Eq, PartialEq)]
pub enum AccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Debug)]
pub enum WriteError {
    PipeClosedAtReadEnd,
    Unexpected(String),
}

pub trait Filesystem: std::fmt::Debug + Send {
    fn root_inode_id(&self) -> InodeIdentifier;

    fn pipe(&mut self) -> Result<Ino> {
        Err("Only pipefs supports pipes".to_owned())
    }

    fn ioctl(&mut self, inode_number: Ino, req: IoctlRequest) -> Result<()>;

    fn create(
        &mut self,
        parent_directory: InodeIdentifier,
        file_type: FileType,
        permissions: FilePermissions,
    ) -> Result<Ino>;

    fn truncate(&mut self, inode_number: Ino) -> Result<()>;

    fn remove(&mut self, inode_number: Ino) -> Result<()>;

    fn inode(&self, inode_number: Ino) -> Option<Inode>;

    fn add_directory_entry(
        &mut self,
        directory: Ino,
        name: String,
        child: InodeIdentifier,
    ) -> Result<()>;

    fn remove_directory_entry(&mut self, directory: Ino, child: InodeIdentifier) -> Result<()>;

    fn directory_entries(&mut self, directory: Ino) -> Result<Vec<DirectoryEntry>>;

    fn update_inode_parent(&mut self, inode_number: Ino, new_parent: InodeIdentifier) -> bool;

    fn open(&mut self, inode_number: Ino, id: OpenFileId, access_mode: AccessMode) -> Result<()>;

    fn close(&mut self, id: OpenFileId);

    fn read(
        &mut self,
        inode_number: Ino,
        id: OpenFileId,
        buf: &mut [u8],
        file_offset: usize,
    ) -> Result<Option<usize>>;

    fn write(
        &mut self,
        inode_number: Ino,
        buf: &[u8],
        file_offset: usize,
    ) -> std::result::Result<usize, WriteError>;
}

/// aka file description (POSIX) or file handle
#[derive(Debug)]
struct OpenFile {
    inode_id: InodeIdentifier,
    offset: usize,
    // Tracks whether any FD refers to this file (meaning we can't remove it)
    fd_references: Weak<OpenFileId>,
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
        mainfs
            .add_directory_entry(
                root_inode_id.number,
                "proc".to_owned(),
                procfs.root_inode_id(),
            )
            .expect("Add proc to root dir");
        let pipefs = PipeFilesystem::new();

        let mut fs: HashMap<FilesystemId, Box<dyn Filesystem>> = HashMap::new();
        fs.insert(FilesystemId::Main, Box::new(mainfs));
        fs.insert(FilesystemId::Proc, Box::new(procfs));
        fs.insert(FilesystemId::Pipe, Box::new(pipefs));

        Self {
            fs,
            next_open_file_id: OpenFileId(0),
            open_files: Default::default(),
        }
    }

    pub fn root_inode_id(&self) -> InodeIdentifier {
        let mainfs = self.fs.get(&FilesystemId::Main).unwrap();
        mainfs.root_inode_id()
    }

    pub fn mount_filesystem(&mut self, name: String, filesystem: impl Filesystem + 'static) {
        let mainfs = self.fs.get_mut(&FilesystemId::Main).unwrap();
        let root_inode_id = mainfs.root_inode_id();
        mainfs
            .add_directory_entry(root_inode_id.number, name, filesystem.root_inode_id())
            .expect("Add dev to root dir");

        self.fs.insert(FilesystemId::Dev, Box::new(filesystem));
    }

    pub fn create_file<S: Into<String>>(
        &mut self,
        path: S,
        file_type: FileType,
        permissions: FilePermissions,
        cwd: InodeIdentifier,
    ) -> SysResult<()> {
        let path = path.into();
        let parts: Vec<&str> = path.split('/').collect();
        let parent_inode = self
            .resolve_from_parts(&parts[..parts.len() - 1], cwd)
            .ok_or(Ecode::Enoent)?;
        let parent_id = parent_inode.id;

        if !parent_inode.is_dir() {
            return Err(Ecode::Enotdir);
        }

        let name = parts[parts.len() - 1].to_owned();

        if self._list_dir(parent_id).iter().any(|x| x.name == name) {
            return Err(Ecode::Eexist);
        }

        let filesystem_id = parent_inode.id.filesystem_id;

        {
            let mut processes = lock_global_process_table();
            let process = processes.current();

            if !self.has_write_permission(process, &parent_inode) {
                return Err(Ecode::Eacces);
            }
            // We drop the process lock before doing any more FS operations
        }

        let fs = self.fs.get_mut(&filesystem_id).unwrap();
        let new_ino = fs.create(parent_inode.id, file_type, permissions).unwrap();
        fs.add_directory_entry(
            parent_inode.id.number,
            name,
            InodeIdentifier {
                filesystem_id,
                number: new_ino,
            },
        )
        .unwrap();

        Ok(())
    }

    pub fn unlink_file(&mut self, path: &str, cwd: InodeIdentifier) -> SysResult<()> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd).ok_or(Ecode::Enoent)?;
        let inode_id = inode.id;

        if inode.file_type == FileType::Directory {
            return Err(Ecode::Eisdir);
        }
        let parent_id = inode.parent_id;

        let mut processes = lock_global_process_table();
        if !self.has_write_permission(processes.current(), &inode) {
            // TODO is it the parent dir's permissions that should matter?
            return Err(Ecode::Eperm);
        }

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        fs.remove(inode_id.number).unwrap();
        let parent_fs = self.fs.get_mut(&parent_id.filesystem_id).unwrap();
        parent_fs
            .remove_directory_entry(parent_id.number, inode_id)
            .unwrap();
        Ok(())
    }

    fn has_write_permission(&self, process: &mut Process, inode: &Inode) -> bool {
        let is_owner = process.uid == inode.user_id;
        let permissions = inode.permissions;
        is_owner && permissions.owner_write() || permissions.others_write()
    }

    pub fn rename_file<S: Into<String>>(
        &mut self,
        old_path: &str,
        new_path: S,
        cwd: InodeIdentifier,
    ) -> SysResult<()> {
        //BUG: "mv myfile proc" works today and it replaces the proc dir with our file
        //TODO: handle replacing existing file
        let new_path = new_path.into();

        let old_parts: Vec<&str> = old_path.split('/').collect();
        let inode = self
            .resolve_from_parts(&old_parts, cwd)
            .ok_or(Ecode::Enoent)?;
        let inode_id = inode.id;
        let old_parent_id = inode.parent_id;

        if inode.file_type == FileType::Directory {
            //TODO Handle moving directory
            return Err(Ecode::Custom("Cannot move directory (yet)".to_owned()));
        }

        let mut processes = lock_global_process_table();
        if !self.has_write_permission(processes.current(), &inode) {
            return Err(Ecode::Eperm);
        }

        let new_parts: Vec<&str> = new_path.split('/').collect();
        let new_base_name = new_parts[new_parts.len() - 1].to_owned();
        let new_parent_inode = self
            .resolve_from_parts(&new_parts[..new_parts.len() - 1], cwd)
            .ok_or(Ecode::Enoent)?;
        if new_parent_inode.id.filesystem_id != inode_id.filesystem_id {
            return Err(Ecode::Exdev);
        }
        let new_parent_id = new_parent_inode.id;

        if new_parent_inode.file_type != FileType::Directory {
            return Err(Ecode::Enotdir);
        }

        let old_parent_inode = self
            .inode(old_parent_id)
            .ok_or_else(|| Ecode::Custom("Old parent doesn't exist".to_owned()))?;

        assert!(old_parent_inode.is_dir());

        //HACK: Assume everything is on same fs
        let fs = self.fs.get_mut(&old_parent_inode.id.filesystem_id).unwrap();

        if !fs.update_inode_parent(inode_id.number, new_parent_id) {
            panic!("We have checked that the inode exists");
        }
        fs.remove_directory_entry(old_parent_id.number, inode_id)
            .unwrap();
        fs.add_directory_entry(new_parent_id.number, new_base_name, inode_id)
            .unwrap();
        Ok(())
    }

    pub fn stat_file(&mut self, path: &str, cwd: InodeIdentifier) -> SysResult<FileStat> {
        //TODO make cwd optional
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd).ok_or(Ecode::Enoent)?;

        let permissions = inode.permissions;

        Ok(FileStat {
            file_type: inode.file_type,
            size: inode.size,
            permissions,
            inode_id: inode.id,
            user_id: inode.user_id,
        })
    }

    pub fn list_dir(&mut self, open_file_id: OpenFileId) -> Vec<DirectoryEntry> {
        let inode_id = self.open_files[&open_file_id].inode_id;
        self._list_dir(inode_id)
    }

    fn _list_dir(&mut self, inode_id: InodeIdentifier) -> Vec<DirectoryEntry> {
        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        fs.directory_entries(inode_id.number).unwrap()
    }

    pub fn open_file(
        &mut self,
        path: &str,
        cwd: InodeIdentifier,
        flags: OpenFlags,
        creation_file_permissions: Option<FilePermissions>,
    ) -> SysResult<Arc<OpenFileId>> {
        let access_mode = parse_access_mode(flags).ok_or(Ecode::Einval)?;
        let parts: Vec<&str> = path.split('/').collect();
        let inode = match self.resolve_from_parts(&parts, cwd) {
            Some(inode) => inode,
            None if flags.contains(OpenFlags::CREATE) => {
                //FUTURE: this is all very inefficient. We should take better care
                //not to redo path resolves
                let permissions = creation_file_permissions.expect("No file permissions specified");
                self.create_file(path, FileType::Regular, permissions, cwd)?;
                self.resolve_from_parts(&parts, cwd)
                    .expect("must exist now")
            }

            None => return Err(Ecode::Enoent),
        };

        let inode_id = inode.id;

        if flags.contains(OpenFlags::TRUNCATE) && inode.file_type != FileType::CharacterDevice {
            let mut processes = lock_global_process_table();
            if !self.has_write_permission(processes.current(), &inode) {
                return Err(Ecode::Eacces);
            }
            // We release the process lock before doing any more FS operations
            drop(processes);

            let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
            fs.truncate(inode_id.number).unwrap();
        }

        let open_file_id = self.next_open_file_id;
        let fd_reference = Arc::new(open_file_id);
        self.open_files.insert(
            open_file_id,
            OpenFile {
                inode_id,
                offset: 0,
                fd_references: Arc::downgrade(&fd_reference),
            },
        );
        self.next_open_file_id = OpenFileId(self.next_open_file_id.0 + 1);

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();

        //TODO do we need to delegate this, or is it enough that the
        //VFS keeps track of open files?
        fs.open(inode_id.number, open_file_id, access_mode).unwrap();
        Ok(fd_reference)
    }

    pub fn create_pipe(&mut self) -> (Arc<OpenFileId>, Arc<OpenFileId>) {
        let pipefs = self
            .fs
            .get_mut(&FilesystemId::Pipe)
            .expect("pipefs must exist");

        let inode_number = pipefs.pipe().unwrap();
        let inode_id = InodeIdentifier {
            filesystem_id: FilesystemId::Pipe,
            number: inode_number,
        };

        //TODO This is all weird. Pipefs doesn't care about us
        // opening / closing the pipe

        // Set up the read-end
        let read_id = self.next_open_file_id;
        let read_fd_reference = Arc::new(read_id);
        self.open_files.insert(
            read_id,
            OpenFile {
                inode_id,
                offset: 0,
                fd_references: Arc::downgrade(&read_fd_reference),
            },
        );
        self.next_open_file_id = OpenFileId(self.next_open_file_id.0 + 1);
        pipefs
            .open(inode_number, read_id, AccessMode::ReadOnly)
            .unwrap();

        // Set up the write end
        let write_id = self.next_open_file_id;
        let write_fd_reference = Arc::new(write_id);
        self.open_files.insert(
            write_id,
            OpenFile {
                inode_id,
                offset: 0,
                fd_references: Arc::downgrade(&write_fd_reference),
            },
        );
        self.next_open_file_id = OpenFileId(self.next_open_file_id.0 + 1);
        pipefs
            .open(inode_number, write_id, AccessMode::WriteOnly)
            .unwrap();

        (read_fd_reference, write_fd_reference)
    }

    pub fn close_file(&mut self, ref_counted_id: Arc<OpenFileId>) {
        eprintln!(
            "DEBUG: VFS close_file({:?}) strong count before release: {}",
            ref_counted_id,
            Arc::strong_count(&ref_counted_id)
        );
        let id: OpenFileId = *ref_counted_id;
        drop(ref_counted_id); //one less fd that refers to this OpenFile

        let open_file = &self.open_files[&id];
        let some_fd_remains = open_file.fd_references.strong_count() > 0;

        eprintln!(
            "DEBUG: VFS close_file({:?}) - some fd remains? {}. strong count: {}",
            id,
            some_fd_remains,
            open_file.fd_references.strong_count()
        );
        if !some_fd_remains {
            let fs = self.fs.get_mut(&open_file.inode_id.filesystem_id).unwrap();
            self.open_files.remove(&id);
            fs.close(id)
        }
    }

    fn get_open_file_mut(&mut self, id: OpenFileId) -> &mut OpenFile {
        self.open_files.get_mut(&id).expect("Open file not found")
    }

    pub fn ioctl(&mut self, open_file_id: OpenFileId, req: IoctlRequest) {
        let inode_id = self.get_open_file_mut(open_file_id).inode_id;
        let inode_number = inode_id.number;

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        fs.ioctl(inode_number, req).unwrap();
    }

    pub fn read_file(
        &mut self,
        open_file_id: OpenFileId,
        buf: &mut [u8],
    ) -> SysResult<Option<usize>> {
        let (inode_id, offset) = {
            let open_file = self.get_open_file_mut(open_file_id);
            (open_file.inode_id, open_file.offset)
        };

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        let inode = fs.inode(inode_id.number).unwrap();
        if inode.file_type == FileType::Directory {
            return Err(Ecode::Eisdir);
        }
        let n_read = match fs.read(inode_id.number, open_file_id, buf, offset).unwrap() {
            Some(n) => n,
            // Would need to block
            None => return Ok(None),
        };

        let open_file = self.get_open_file_mut(open_file_id);
        open_file.offset += n_read;
        Ok(Some(n_read))
    }

    pub fn write_file(&mut self, open_file_id: OpenFileId, buf: &[u8]) -> SysResult<usize> {
        let (inode_id, offset) = {
            let open_file = self.get_open_file_mut(open_file_id);
            (open_file.inode_id, open_file.offset)
        };

        let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
        let n_read = match fs.write(inode_id.number, buf, offset) {
            Ok(n) => Ok(n),
            Err(WriteError::PipeClosedAtReadEnd) => Err(Ecode::Epipe),
            Err(other_error) => panic!("Unexpected write error: {:?}", other_error),
        }?;

        let open_file = self.get_open_file_mut(open_file_id);
        open_file.offset += n_read;
        Ok(n_read)
    }

    pub fn seek(&mut self, open_file_id: OpenFileId, offset: SeekOffset) -> SysResult<()> {
        match offset {
            SeekOffset::Set(offset) => {
                let mut open_file = self.get_open_file_mut(open_file_id);
                open_file.offset = offset;
            }
            SeekOffset::End(relative_offset) => {
                let inode_id = self.get_open_file_mut(open_file_id).inode_id;
                let fs = self.fs.get_mut(&inode_id.filesystem_id).unwrap();
                let size = fs.inode(inode_id.number).unwrap().size;
                let offset = (size as i64 + relative_offset) as usize;
                let mut open_file = self.get_open_file_mut(open_file_id);
                open_file.offset = offset;
            }
        }
        Ok(())
    }

    pub fn path_from_inode(&mut self, inode_id: InodeIdentifier) -> Result<String> {
        let mut parts_reverse: Vec<String> = Vec::new();
        let mut inode = self
            .inode(inode_id)
            .ok_or_else(|| "Parent doesn't exist".to_owned())?;

        loop {
            if inode.parent_id == inode.id {
                // The root inode has itself as a parent
                break;
            }

            let parent_inode = self
                .inode(inode.parent_id)
                .ok_or_else(|| "Parent doesn't exist".to_owned())?;
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

    fn resolve_from_parts(&mut self, mut parts: &[&str], cwd: InodeIdentifier) -> Option<Inode> {
        //TODO Make cwd optional. Should be possible to call this with absolute paths w/o cwd
        let mut inode = match parts.get(0) {
            Some(&"") => {
                // (empty string here means the path starts with '/', since we split on it)
                // We got an absolute path. Start from root.
                parts = &parts[1..];

                let fs = self.fs.get(&FilesystemId::Main).unwrap();
                let root_inode_number = fs.root_inode_id().number;
                Some(
                    fs.inode(root_inode_number)
                        .expect("Must have root inode with number 0"),
                )
            }

            // resolving a file in cwd
            None => self.inode(cwd),

            // resolving something further down in the tree
            Some(_) => self.inode(cwd),
        }?;

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
                        .directory_entries(inode_id.number)
                        .unwrap()
                        .into_iter()
                        .find(|entry| entry.name == **part)?
                        .inode_id
                }
            };

            inode = self.inode(next_id)?;
        }

        let inode_id = inode.id;
        self.inode(inode_id)
    }

    pub fn resolve_directory(&mut self, path: &str, cwd: InodeIdentifier) -> SysResult<Inode> {
        let parts: Vec<&str> = path.split('/').collect();
        let inode = self.resolve_from_parts(&parts, cwd).ok_or(Ecode::Enoent)?;
        if inode.file_type != FileType::Directory {
            return Err(Ecode::Custom(format!("Not a directory: {}", path)));
        }
        Ok(inode)
    }

    fn inode(&self, inode_id: InodeIdentifier) -> Option<Inode> {
        let fs = self.fs.get(&inode_id.filesystem_id).unwrap();
        fs.inode(inode_id.number)
    }
}

fn parse_access_mode(flags: OpenFlags) -> Option<AccessMode> {
    let r = flags.contains(OpenFlags::READ_ONLY);
    let w = flags.contains(OpenFlags::WRITE_ONLY);
    let rw = flags.contains(OpenFlags::READ_WRITE);
    match (r, w, rw) {
        (true, false, false) => Some(AccessMode::ReadOnly),
        (false, true, false) => Some(AccessMode::WriteOnly),
        (false, false, true) => Some(AccessMode::ReadWrite),
        _ => None,
    }
}
