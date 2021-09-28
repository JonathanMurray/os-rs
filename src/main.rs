mod devfs;
mod procfs;
mod regularfs;
mod shell;
mod sys;
mod util;
mod vfs;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::devfs::DevFilesystem;
use crate::shell::ShellProcess;
use crate::sys::{
    OpenFlags, ProcessHandle, SpawnAction, SpawnFds, SpawnUid, System, WaitPidOptions,
    WaitPidTarget, GLOBAL_PROCESS_TABLE,
};
use crate::util::{FilePermissions, FileType, Pid, Uid};
use crate::vfs::VirtualFilesystemSwitch;

type Result<T> = std::result::Result<T, String>;

#[tokio::main]
pub async fn main() {
    println!("Operating System initializing...");

    eprintln!("--------------------------------");

    let init_pid = Pid(0);
    let mut vfs = VirtualFilesystemSwitch::new();
    let root_inode_id = vfs.root_inode_id();
    let devfs = DevFilesystem::new(root_inode_id, init_pid);
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
            "init".to_owned(),
            init_pid,
            Uid(0),
            None,
            None,
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
        .sc_create("/bin", FileType::Directory, FilePermissions::ReadOnly)
        .unwrap();

    create_text_file(&mut handle, "/bin/script", "PROGRAM:script\n").unwrap();
    create_text_file(&mut handle, "/bin/sleep", "PROGRAM:sleep\n").unwrap();
    create_text_file(&mut handle, "/bin/background", "PROGRAM:background\n").unwrap();
    create_text_file(&mut handle, "/bin/shell", "PROGRAM:shell\n").unwrap();
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
            "/bin/shell",
            SpawnFds::Set(terminal_fd, terminal_fd),
            SpawnUid::Uid(shell_uid),
            Some(SpawnAction::ClaimTerminal(terminal_fd)),
        )
        .expect("spawn shell from init");
    handle.sc_close(terminal_fd).unwrap();
    handle
        .sc_spawn(
            "/bin/background",
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
            .sc_spawn("/bin/script", SpawnFds::Inherit, SpawnUid::Inherit, None)
            .expect("spawn child from init");
        let child_result = handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::Default)
            .unwrap();
        handle
            .sc_write(log_fd, format!("{:?}\n", child_result).as_bytes())
            .unwrap();

        let sleep_pid = handle
            .sc_spawn("/bin/sleep", SpawnFds::Inherit, SpawnUid::Inherit, None)
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

fn create_text_file(handle: &mut ProcessHandle, path: &str, content: &str) -> Result<()> {
    let fd = handle.sc_open(path, OpenFlags::CREATE, Some(FilePermissions::ReadWrite))?;
    //TODO we leak the FD if write fails
    let content = content.as_bytes();
    let n_written = handle.sc_write(fd, content)?;
    assert_eq!(n_written, content.len(), "We didn't writ the whole file");
    handle.sc_close(fd)
}

fn run_new_proc(mut handle: ProcessHandle) {
    let name = handle.process_name();

    if let Err(err) = handle.sc_stat(&name) {
        eprintln!("did not find {}: {}", name, err);
        handle.sc_exit(1);
        return;
    }

    let fd = handle.sc_open(&name, OpenFlags::empty(), None).unwrap();
    //TODO: introduce a file abstraction that makes these things easier
    let mut buf = vec![0; 1024];
    let n_read = handle.sc_read(fd, &mut buf).unwrap().unwrap();
    handle.sc_close(fd).unwrap();
    assert!(n_read < buf.len(), "We may not have read the full file");
    let content = match std::str::from_utf8(&buf[..n_read]) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Not a valid executable: {}. Does not contain text", name);
            handle.sc_exit(2);
            return;
        }
    };

    match content {
        "PROGRAM:script\n" => run_script_proc(handle),
        "PROGRAM:background\n" => run_background_proc(handle),
        "PROGRAM:shell\n" => run_shell_proc(handle),
        "PROGRAM:sleep\n" => run_sleep_proc(handle),
        _ => {
            eprintln!("Not a valid executable: {}. ({:?})", name, content);
            handle.sc_exit(2);
        }
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

fn run_background_proc(mut sys: ProcessHandle) {
    sys.sc_create("README", FileType::Regular, FilePermissions::ReadWrite)
        .expect("Create README file");
    //TODO: create README through open
    let fd = sys
        .sc_open("README", OpenFlags::empty(), None)
        .expect("Open README file");
    let readme = "Commands:\nstat\ncat\nls\nll\ntouch\nmkdir\ncd\nrm\nmv\nhelp\n";
    sys.sc_write(fd, readme.as_bytes())
        .expect("Write to README");
    sys.sc_close(fd).expect("Close README");

    sys.sc_create("uptime", FileType::Regular, FilePermissions::ReadWrite)
        .expect("Create uptime file");
    //TODO create through open
    let fd = sys
        .sc_open("uptime", OpenFlags::empty(), None)
        .expect("Open uptime file");
    eprintln!("background proc opened uptime file with fd: {}", fd);
    let mut secs = 0_u64;
    for _ in 0..50 {
        sys = if let Some(h) = sys.handle_signals() {
            h
        } else {
            return;
        };

        std::thread::sleep(Duration::from_secs(1));
        secs += 1;
        {
            sys.sc_seek(fd, 0).expect("seek in uptime file");
            sys.sc_write(
                fd,
                format!("System has been running for {} seconds.\n", secs).as_bytes(),
            )
            .expect("Write to uptime file");
        }
    }
    sys.sc_close(fd).expect("Close uptime file");
}

fn run_shell_proc(handle: ProcessHandle) {
    let shell = ShellProcess::new(handle);
    shell.run();
}
