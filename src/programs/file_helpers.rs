use crate::sys::{OpenFlags, ProcessHandle};
use crate::util::{Ecode, Fd, FileStat, SysResult};

pub struct FileReader<'a> {
    path: &'a str,
    fd: Option<Fd>,
    handle: &'a ProcessHandle,
}

impl<'a> FileReader<'a> {
    pub fn open(handle: &'a ProcessHandle, path: &'a str) -> SysResult<Self> {
        let fd = handle.sc_open(path, OpenFlags::empty(), None)?;
        Ok(Self {
            path,
            fd: Some(fd),
            handle,
        })
    }

    pub fn stat(&mut self) -> SysResult<FileStat> {
        self.handle.sc_stat(self.path)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> SysResult<Option<usize>> {
        self.handle.sc_read(self.fd.unwrap(), buf)
    }

    pub fn read_fully(&mut self) -> SysResult<Vec<u8>> {
        let mut vec = Vec::new();
        let mut buf = [0; 1024];
        loop {
            match self.handle.sc_read(self.fd.unwrap(), &mut buf) {
                Ok(Some(0)) => return Ok(vec),
                Ok(Some(n)) => {
                    vec.extend(&buf[..n]);
                }
                Ok(None) => {
                    return Err(Ecode::Custom("Would need to block to read".to_owned()));
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn read_to_string(&mut self) -> SysResult<String> {
        self.read_fully()
            .map(|content| String::from_utf8_lossy(&content).to_string())
    }

    pub fn close(mut self) {
        self._ensure_closed()
    }

    pub fn _ensure_closed(&mut self) {
        if let Some(fd) = self.fd.take() {
            if let Err(e) = self.handle.sc_close(fd) {
                println!("WARN: Failed to close {} (fd: {}): {}", self.path, fd, e);
            }
        }
    }
}

impl Drop for FileReader<'_> {
    fn drop(&mut self) {
        self._ensure_closed()
    }
}
