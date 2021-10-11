use std::time::Duration;

use crate::programs::file_helpers::FileReader;
use crate::sys::{OpenFlags, ProcessHandle};
use crate::util::{FilePermissions, SysResult};

pub mod background;
pub mod cat;
pub mod dump;
pub mod echo;
pub mod file;
pub mod file_helpers;
pub mod pipedemo;
pub mod shell;
pub mod utils;
pub mod wc;

const PROGRAM_MAGIC_CODE: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

pub fn add_program_files_to_bin_dir(handle: &mut ProcessHandle) {
    create_program_file(handle, "script").unwrap();
    create_program_file(handle, "sleep").unwrap();
    create_program_file(handle, "background").unwrap();
    create_program_file(handle, "shell").unwrap();
    create_program_file(handle, "file").unwrap();
    create_program_file(handle, "touch").unwrap();
    create_program_file(handle, "dump").unwrap();
    create_program_file(handle, "cat").unwrap();
    create_program_file(handle, "pipedemo").unwrap();
    create_program_file(handle, "echo").unwrap();
    create_program_file(handle, "wc").unwrap();
}

fn create_program_file(handle: &mut ProcessHandle, program_name: &str) -> SysResult<()> {
    let path = format!("/bin/{}", program_name);
    let fd = handle.sc_open(
        &path,
        OpenFlags::WRITE_ONLY | OpenFlags::CREATE,
        Some(FilePermissions::new(7, 5)),
    )?;
    //TODO we leak the FD if write fails
    let mut content = Vec::new();
    content.extend(PROGRAM_MAGIC_CODE);
    content.extend(program_name.as_bytes());
    content.extend("\n".as_bytes());
    let n_written = handle.sc_write(fd, &content[..])?;
    assert_eq!(n_written, content.len(), "We didn't write the whole file");
    handle.sc_close(fd)
}

pub fn run_program(handle: ProcessHandle) {
    let args = handle.clone_args();
    let name = &args[0];

    if let Err(err) = handle.sc_stat(name) {
        handle
            .stderr(format!("Couldn't run {}: {}\n", name, err))
            .unwrap();
        handle.sc_exit(1);
        return;
    }

    let mut f = FileReader::open(&handle, name).unwrap_or_else(|e| {
        panic!("Failed to open {}: {}", name, e);
    });
    let buf = f.read_fully().unwrap();
    f.close();

    match &buf[..].strip_prefix(PROGRAM_MAGIC_CODE) {
        None => {
            handle
                .stderr(format!("{} is not an executable\n", name))
                .unwrap();
            handle.sc_exit(2);
        }
        Some(rest) => match std::str::from_utf8(rest) {
            Ok("script\n") => run_script_proc(handle),
            Ok("background\n") => background::run_background_proc(handle),
            Ok("shell\n") => shell::run(handle, args),
            Ok("sleep\n") => run_sleep_proc(handle),
            Ok("file\n") => file::run_file_proc(handle, args),
            Ok("touch\n") => utils::run_touch_proc(handle, args),
            Ok("dump\n") => dump::run_dump_proc(handle, args),
            Ok("cat\n") => cat::run_cat_proc(handle, args),
            Ok("pipedemo\n") => pipedemo::run(handle, args),
            Ok("echo\n") => echo::run(handle, args),
            Ok("wc\n") => wc::run(handle, args),
            _ => {
                eprintln!("Not a valid executable: {}. ({:?})", name, rest);
                handle.sc_exit(2);
            }
        },
    }
}

fn run_sleep_proc(handle: ProcessHandle) {
    // TODO do this with syscall so that kernel can
    // handle any pending signals
    for _ in 0..50 {
        handle.handle_signals();
        std::thread::sleep(Duration::from_millis(100));
    }

    handle
        .sc_write(1, "Woke up\n".as_bytes())
        .expect("writing to stdout");

    handle.sc_exit(0);
}

fn run_script_proc(handle: ProcessHandle) {
    for _ in 0..5 {
        handle.handle_signals();
        std::thread::sleep(Duration::from_secs(1));
    }
    handle.sc_exit(0);
}
