use crate::sys::{OpenFlags, ProcessHandle};
use crate::util::{Ecode, Fd};
use std::time::Duration;

type Result<T> = std::result::Result<T, String>;

pub fn run_cat_proc(mut handle: ProcessHandle, args: Vec<String>) {
    let result = match args.get(1) {
        Some(path) => cat_file(&mut handle, path),
        None => cat_fd(&mut handle, 0),
    };

    if let Err(e) = result {
        handle.stderr(format!("Error: {}\n", e)).unwrap();
    }
}

fn cat_file(handle: &mut ProcessHandle, path: &str) -> Result<()> {
    let fd = handle.sc_open(path, OpenFlags::READ_ONLY, None)?;
    let result = cat_fd(handle, fd);
    handle.sc_close(fd).expect("Closing cat file");
    result
}

fn cat_fd(handle: &mut ProcessHandle, fd: Fd) -> Result<()> {
    let count = 256;
    loop {
        handle.handle_signals();
        match handle.sc_sendfile(1, fd, count) {
            Ok(0) => break, //EOF
            Ok(_) => {}
            Err(Ecode::Eagain) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
