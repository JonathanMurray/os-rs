use crate::programs::file_helpers::FileReader;
use crate::sys::ProcessHandle;
use crate::util::FileType;

pub fn run_file_proc(mut handle: ProcessHandle, args: Vec<String>) {
    let (code, message) = _run_file_proc(&mut handle, args);
    handle
        .sc_write(1, format!("{}\n", message).as_bytes())
        .unwrap();
    handle.sc_exit(code);
}

pub fn _run_file_proc(handle: &mut ProcessHandle, args: Vec<String>) -> (u32, String) {
    let path = match args.get(1) {
        None => {
            return (1, "Missing path arg".to_owned());
        }
        Some(path) => path,
    };

    let mut reader = match FileReader::open(handle, path) {
        Err(e) => {
            return (1, format!("Failed to open {}: {}", path, e));
        }
        Ok(r) => r,
    };

    match reader.stat().expect("Stat should work now").file_type {
        FileType::Directory => {
            return (0, "Directory".to_owned());
        }
        FileType::CharacterDevice => {
            return (0, "Character device".to_owned());
        }
        _ => {}
    }

    let mut buf = [0; 1024];
    let n = match reader.read(&mut buf) {
        Err(e) => {
            return (1, format!("Failed to read {}: {}", path, e));
        }
        Ok(n) => n,
    };

    let n = n.expect("TODO: handle blocking file read");

    if n == 0 {
        return (0, "Empty file".to_owned());
    }

    if buf.starts_with(&[0xDE, 0xAD, 0xBE, 0xEF]) {
        return (0, "Executable program".to_owned());
    }

    if std::str::from_utf8(&buf[..n]).is_ok() {
        return (0, "UTF-8 text".to_owned());
    }

    (0, "Unknown file format".to_owned())
}
