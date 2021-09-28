use crate::sys::{OpenFlags, ProcessHandle};
use crate::util::FileType;
pub fn run_file_proc(mut handle: ProcessHandle, args: Vec<String>) {
    let path = match args.get(1) {
        None => {
            handle.sc_write(1, "Missing path arg\n".as_bytes()).unwrap();
            handle.sc_exit(1);
            return;
        }
        Some(path) => path,
    };

    let fd = match handle.sc_open(path, OpenFlags::empty(), None) {
        Err(e) => {
            handle
                .sc_write(1, format!("Failed to open {}: {}\n", path, e).as_bytes())
                .unwrap();
            handle.sc_exit(1);
            return;
        }
        Ok(fd) => fd,
    };

    match handle
        .sc_stat(path)
        .expect("Stat should work now")
        .file_type
    {
        FileType::Directory => {
            handle.sc_write(1, "Directory\n".as_bytes()).unwrap();
            return;
        }
        FileType::CharacterDevice => {
            handle.sc_write(1, "Character device\n".as_bytes()).unwrap();
            return;
        }
        _ => {}
    }

    let mut buf = [0; 1024];

    let n = match handle.sc_read(fd, &mut buf) {
        Err(e) => {
            handle
                .sc_write(1, format!("Failed to read {}: {}\n", path, e).as_bytes())
                .unwrap();
            handle.sc_exit(1);
            return;
        }
        Ok(n) => n,
    };

    let n = n.expect("TODO: handle blocking file read");

    if n == 0 {
        handle.sc_write(1, "Empty file\n".as_bytes()).unwrap();
        return;
    }

    if buf.starts_with(&[0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF]) {
        handle
            .sc_write(1, "Executable program\n".as_bytes())
            .unwrap();
        return;
    }

    if std::str::from_utf8(&buf[..n]).is_ok() {
        handle.sc_write(1, "UTF-8 text\n".as_bytes()).unwrap();
        return;
    }

    handle
        .sc_write(1, "Unknown file format\n".as_bytes())
        .unwrap();
}
