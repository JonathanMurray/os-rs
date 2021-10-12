use crate::programs::file_helpers::FileReader;
use crate::sys::{ProcessHandle, SeekOffset};
use crate::util::Ecode;

use std::time::Duration;

type Result<T> = std::result::Result<T, String>;

pub fn run(mut handle: ProcessHandle, args: Vec<String>) {
    let result = match args.get(1) {
        Some(path) => _run(&mut handle, path),
        None => {
            handle
                .stderr(format!("{} error: missing arg", args[0]))
                .unwrap();
            handle.sc_exit(0);
            return;
        }
    };

    if let Err(e) = result {
        handle.stderr(format!("Error: {}\n", e)).unwrap();
    }
}

fn _run(handle: &mut ProcessHandle, path: &str) -> Result<()> {
    let mut f = FileReader::open(handle, path)?;
    f.seek(SeekOffset::End(0)).unwrap();
    let mut buf = [0; 1024];
    // This program can only finish by being interrupted/killed
    loop {
        match f.read(&mut buf)? {
            None | Some(0) => {
                eprintln!("[tail] nothing to read...");
                match handle.sc_nanosleep(Duration::from_millis(100)) {
                    Ok(_) | Err(Ecode::Eintr) => Ok(()),
                    unexpected_error => unexpected_error,
                }?;
                continue;
            }
            Some(n) => {
                eprintln!("[tail] We got {} bytes", n);
                handle.sc_write(1, &buf[..n]).unwrap();
            }
        }
    }
}
