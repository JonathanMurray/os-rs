use crate::sys::{OpenFlags, ProcessHandle, SeekOffset};
use crate::util::{Fd, FileStat, SysResult};

pub struct FileReader<'a> {
    path: &'a str,
    fd: Option<Fd>,
    handle: &'a ProcessHandle,
}

impl<'a> FileReader<'a> {
    pub fn open(handle: &'a ProcessHandle, path: &'a str) -> SysResult<Self> {
        let fd = handle.sc_open(path, OpenFlags::READ_ONLY, None)?;
        Ok(Self {
            path,
            fd: Some(fd),
            handle,
        })
    }

    pub fn stat(&mut self) -> SysResult<FileStat> {
        self.handle.sc_stat(self.path)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> SysResult<usize> {
        self.handle.sc_read(self.fd.unwrap(), buf)
    }

    pub fn read_fully(&mut self) -> SysResult<Vec<u8>> {
        let mut vec = Vec::new();
        let mut buf = [0; 1024];
        loop {
            match self.handle.sc_read(self.fd.unwrap(), &mut buf) {
                Ok(0) => return Ok(vec),
                Ok(n) => {
                    vec.extend(&buf[..n]);
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn read_to_string(&mut self) -> SysResult<String> {
        self.read_fully()
            .map(|content| String::from_utf8_lossy(&content).to_string())
    }

    pub fn seek(&mut self, offset: SeekOffset) -> SysResult<()> {
        self.handle.sc_seek(self.fd.unwrap(), offset)
    }

    pub fn close(mut self) {
        self._ensure_closed()
    }

    pub fn _ensure_closed(&mut self) {
        if self.handle.has_died() {
            // Interacting with the handle after the process has died
            // causes a crash. Ideally this would be preventd by
            // the type-system, but making the handle functions require
            // a mutable reference caused lots of headaches.
            eprintln!("[file reader] process has died. Will not try to close");
            return;
        }

        if let Some(fd) = self.fd.take() {
            if let Err(e) = self.handle.sc_close(fd) {
                // This can happen naturally if a process is killed from a signal
                // while owning this file
                eprintln!("WARN: Failed to close {} (fd: {}): {}", self.path, fd, e);
            }
        }
    }
}

impl Drop for FileReader<'_> {
    fn drop(&mut self) {
        self._ensure_closed()
    }
}
