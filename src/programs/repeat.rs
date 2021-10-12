use crate::sys::ProcessHandle;
use crate::util::Ecode;

use std::time::Duration;

type Result<T> = std::result::Result<T, String>;

pub fn run(mut handle: ProcessHandle, args: Vec<String>) {
    let result = match args.get(1) {
        Some(word) => _run(&mut handle, word),
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

fn _run(handle: &mut ProcessHandle, word: &str) -> Result<()> {
    let mut counter = 1;
    // This program can only finish by being interrupted/killed
    loop {
        handle.sc_write(1, format!("{}: ", counter).as_bytes())?;
        handle.sc_write(1, word.as_bytes())?;
        handle.sc_write(1, "\n".as_bytes())?;
        match handle.sc_nanosleep(Duration::from_millis(500)) {
            Ok(_) | Err(Ecode::Eintr) => Ok(()),
            unexpected_error => unexpected_error,
        }
        .unwrap();
        counter += 1;
    }
}
