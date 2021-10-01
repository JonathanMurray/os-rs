mod devfs;
mod procfs;
mod programs;
mod regularfs;
mod sys;
mod util;
mod vfs;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::devfs::DevFilesystem;
use crate::programs::background;
use crate::programs::dump;
use crate::programs::file;
use crate::programs::file_helpers::FileReader;
use crate::programs::shell::ShellProcess;
use crate::programs::utils;

use crate::sys::{
    OpenFlags, ProcessHandle, SpawnAction, SpawnFds, SpawnUid, System, WaitPidOptions,
    WaitPidTarget, GLOBAL_PROCESS_TABLE,
};
use crate::util::{FilePermissions, FileType, Pid, Uid};
use crate::vfs::VirtualFilesystemSwitch;

type Result<T> = std::result::Result<T, String>;

const PROGRAM_MAGIC_CODE: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

#[tokio::main]
pub async fn main() {
    println!("Operating System initializing...");

    eprintln!("--------------------------------");

    let init_pid = Pid(0);
    let mut vfs = VirtualFilesystemSwitch::new();
    let root_inode_id = vfs.root_inode_id();
    let devfs = DevFilesystem::new(root_inode_id);
    let terminal_input = devfs.kernel_terminal_input_writer();
    vfs.mount_filesystem("dev".to_owned(), devfs);
    tokio::task::spawn_blocking(move || run_terminal_handler(terminal_input));

    let sys = System::new(vfs);
    let sys = Arc::new(Mutex::new(sys));

    let liveness = Arc::new(());
    {
        let processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
        let init_handle = System::spawn_process(
            processes,
            sys,
            vec!["init".to_owned()],
            init_pid,
            Uid(0),
            (None, None),
            root_inode_id,
        );
        let liveness = Arc::clone(&liveness);
        tokio::task::spawn_blocking(move || run_init_proc(init_handle, liveness))
    };

    loop {
        std::thread::sleep(Duration::from_millis(20));
        {
            let mut spawn_queue = sys::GLOBAL_PROCESS_SPAWN_QUEUE.lock().unwrap();
            if let Some(new_handle) = spawn_queue.pop_back() {
                tokio::task::spawn_blocking(move || run_new_proc(new_handle));
            }
        }
    }
}

fn run_terminal_handler(terminal_input_writer: Arc<Mutex<Vec<u8>>>) {
    let stdin = io::stdin();
    loop {
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        terminal_input_writer
            .lock()
            .unwrap()
            .extend(input.as_bytes());
    }
}

fn run_init_proc(mut handle: ProcessHandle, liveness_checker: Arc<()>) {
    // Make init's stdin/stdout point at /dev/null. It must be the first file we open
    handle
        .sc_open("/dev/null", OpenFlags::empty(), None)
        .expect("/dev/null must exist for stdin");
    handle
        .sc_open("/dev/null", OpenFlags::empty(), None)
        .expect("/dev/null must exist for stdout");

    handle
        .sc_create("/bin", FileType::Directory, FilePermissions::new(7, 5))
        .unwrap();

    create_program_file(&mut handle, "/bin/script", "script").unwrap();
    create_program_file(&mut handle, "/bin/sleep", "sleep").unwrap();
    create_program_file(&mut handle, "/bin/background", "background").unwrap();
    create_program_file(&mut handle, "/bin/shell", "shell").unwrap();
    create_program_file(&mut handle, "/bin/file", "file").unwrap();
    create_program_file(&mut handle, "/bin/touch", "touch").unwrap();
    create_program_file(&mut handle, "/bin/dump", "dump").unwrap();
    let log_fd = handle
        .sc_open("/dev/log", OpenFlags::empty(), None)
        .unwrap();
    eprintln!("Opened /dev/log with fd: {}", log_fd);
    let terminal_fd = handle
        .sc_open("/dev/terminal", OpenFlags::empty(), None)
        .expect("/dev/terminal must exist to be used as shell stdin");
    let shell_uid = Uid(1);
    handle
        .sc_spawn(
            vec!["/bin/shell".to_owned()],
            SpawnFds::Set(terminal_fd, terminal_fd),
            SpawnUid::Uid(shell_uid),
            Some(SpawnAction::ClaimTerminal(terminal_fd)),
        )
        .expect("spawn shell from init");
    handle.sc_close(terminal_fd).unwrap();
    handle
        .sc_spawn(
            vec!["/bin/background".to_owned()],
            SpawnFds::Inherit,
            SpawnUid::Inherit,
            None,
        )
        .expect("spawn background proc from init");

    handle
        .sc_write(log_fd, "Init starting...\n".as_bytes())
        .unwrap();
    loop {
        handle = match handle.handle_signals() {
            Some(handle) => handle,
            None => {
                println!("WARN: Init process was killed");
                return;
            }
        };

        handle
            .sc_spawn(
                vec!["/bin/script".to_owned()],
                SpawnFds::Inherit,
                SpawnUid::Inherit,
                None,
            )
            .expect("spawn child from init");
        let child_result = handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::Default)
            .unwrap();
        handle
            .sc_write(log_fd, format!("{:?}\n", child_result).as_bytes())
            .unwrap();

        let sleep_pid = handle
            .sc_spawn(
                vec!["/bin/sleep".to_owned()],
                SpawnFds::Inherit,
                SpawnUid::Inherit,
                None,
            )
            .expect("spawn sleep from init");
        handle
            .sc_wait_pid(WaitPidTarget::Pid(sleep_pid), WaitPidOptions::Default)
            .unwrap();

        if Arc::strong_count(&liveness_checker) < 2 {
            break;
        }
    }
    println!("Init process exiting.");
}

fn create_program_file(handle: &mut ProcessHandle, path: &str, program_name: &str) -> Result<()> {
    let fd = handle.sc_open(path, OpenFlags::CREATE, Some(FilePermissions::new(7, 5)))?;
    //TODO we leak the FD if write fails
    let mut content = Vec::new();
    content.extend(PROGRAM_MAGIC_CODE);
    content.extend(program_name.as_bytes());
    content.extend("\n".as_bytes());
    let n_written = handle.sc_write(fd, &content[..])?;
    assert_eq!(n_written, content.len(), "We didn't writ the whole file");
    handle.sc_close(fd)
}

fn run_new_proc(handle: ProcessHandle) {
    let args = handle.clone_args();
    let name = &args[0];

    if let Err(err) = handle.sc_stat(name) {
        handle
            .stdout(format!("Couldn't run {}: {}\n", name, err))
            .unwrap();
        handle.sc_exit(1);
        return;
    }

    let mut f = FileReader::open(&handle, name).unwrap();
    let buf = f.read_fully().unwrap();
    f.close();

    match &buf[..].strip_prefix(PROGRAM_MAGIC_CODE) {
        None => {
            handle
                .stdout(format!("{} is not an executable\n", name))
                .unwrap();
            handle.sc_exit(2);
        }
        Some(rest) => match std::str::from_utf8(rest) {
            Ok("script\n") => run_script_proc(handle),
            Ok("background\n") => background::run_background_proc(handle),
            Ok("shell\n") => ShellProcess::new(handle).run(),
            Ok("sleep\n") => run_sleep_proc(handle),
            Ok("file\n") => file::run_file_proc(handle, args),
            Ok("touch\n") => utils::run_touch_proc(handle, args),
            Ok("dump\n") => dump::run_dump_proc(handle, args),
            _ => {
                eprintln!("Not a valid executable: {}. ({:?})", name, rest);
                handle.sc_exit(2);
            }
        },
    }
}

fn run_sleep_proc(mut handle: ProcessHandle) {
    for _ in 0..5 {
        handle = if let Some(h) = handle.handle_signals() {
            h
        } else {
            return;
        };

        std::thread::sleep(Duration::from_millis(500));
    }

    handle
        .sc_write(1, "Woke up\n".as_bytes())
        .expect("writing to stdout");

    handle.sc_exit(0);
}

fn run_script_proc(mut handle: ProcessHandle) {
    for _ in 0..5 {
        handle = if let Some(h) = handle.handle_signals() {
            h
        } else {
            return;
        };
        std::thread::sleep(Duration::from_secs(1));
    }

    handle.sc_exit(0);
}
