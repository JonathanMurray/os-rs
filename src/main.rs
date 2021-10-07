mod devfs;
mod procfs;
mod programs;
mod regularfs;
mod sys;
mod terminal_driver;
mod util;
mod vfs;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use futures::{join, poll, FutureExt};

use crate::devfs::DevFilesystem;
use crate::programs::background;
use crate::programs::dump;
use crate::programs::file;
use crate::programs::file_helpers::FileReader;
use crate::programs::shell::ShellProcess;
use crate::programs::utils;
use crate::sys::{
    Ecode, OpenFlags, ProcessHandle, ProcessResult, ProcessWasKilledPanic, SpawnAction, SpawnFds,
    SpawnUid, System, WaitPidOptions, WaitPidTarget, GLOBAL_PROCESS_TABLE,
};
use crate::util::{FilePermissions, FileType, InodeIdentifier, Pid, Uid};
use crate::vfs::VirtualFilesystemSwitch;

type Result<T> = std::result::Result<T, String>;

const PROGRAM_MAGIC_CODE: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

#[tokio::main]
pub async fn main() {
    println!("Operating System initializing...");

    eprintln!("--------------------------------");

    let mut vfs = VirtualFilesystemSwitch::new();
    let root_inode_id = vfs.root_inode_id();
    let terminal_out = Arc::new(Mutex::new(Default::default()));
    let devfs = DevFilesystem::new(root_inode_id, Arc::clone(&terminal_out));
    let terminal_in = devfs.terminal_input_feeder();
    vfs.mount_filesystem("dev".to_owned(), devfs);
    let should_thread_exit = Arc::new(AtomicBool::new(false));
    let terminal_driver_fut = {
        let should_exit = Arc::clone(&should_thread_exit);
        tokio::task::spawn_blocking(move || {
            terminal_driver::run(should_exit, terminal_in, terminal_out)
        })
    };

    let sys = System::new(vfs);

    let init_pid = Pid(0);
    let init_fut = tokio::task::spawn_blocking(move || {
        let init_handle = spawn_init_proc(init_pid, sys, root_inode_id);
        run_init_proc(init_handle)
    });

    // fuse needed for select
    let terminal_driver_fut = terminal_driver_fut.fuse();
    let init_fut = init_fut.fuse();

    let mut futs = vec![
        (ThreadId::Pid(init_pid), init_fut),
        (ThreadId::TerminalDriver, terminal_driver_fut),
    ];

    loop {
        let mut finished_threads = HashSet::new();
        let mut should_shut_down = false;
        for (thread_id, f) in futs.iter_mut() {
            match poll!(f) {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    eprintln!("{:?} RESULT: {:?}", thread_id, result);
                    match result {
                        Ok(_) => {}
                        Err(join_error) => {
                            if let Ok(reason) = join_error.try_into_panic() {
                                if reason.downcast_ref::<ProcessWasKilledPanic>().is_some() {
                                    eprintln!("A process was killed: {:?}", thread_id);
                                } else {
                                    let reason = if let Some(s) = reason.downcast_ref::<&str>() {
                                        s
                                    } else if let Some(s) = reason.downcast_ref::<String>() {
                                        s
                                    } else {
                                        ""
                                    };
                                    println!("A thread crashed: {:?} ({}) - Will shut down operating system.", thread_id, reason);
                                    should_shut_down = true;
                                }
                            }
                        }
                    }
                    match thread_id {
                        ThreadId::TerminalDriver => {
                            println!("TERMINAL DRIVER EXITED");
                            should_shut_down = true;
                        }
                        ThreadId::Pid(pid) => {
                            if *pid == init_pid {
                                println!("Init process exited.");
                                should_shut_down = true;
                            }
                        }
                    }
                    finished_threads.insert(*thread_id);
                }
            }
        }
        futs.retain(|(pid, _)| !finished_threads.contains(pid));
        if should_shut_down {
            break;
        }

        std::thread::sleep(Duration::from_millis(20));

        {
            let mut spawn_queue = sys::GLOBAL_PROCESS_SPAWN_QUEUE.lock().unwrap();
            if let Some(new_handle) = spawn_queue.pop_back() {
                let pid = new_handle.pid();
                let f = tokio::task::spawn_blocking(move || run_program_proc(new_handle));
                futs.push((ThreadId::Pid(pid), f.fuse()));
            }
        }
    }

    eprintln!("Exited loop in main method");
    should_thread_exit.store(true, Ordering::Relaxed);

    for (id, f) in futs {
        // Wait for terminal driver to exit, so that we don't
        // exit the program with a messed up terminal state
        if id == ThreadId::TerminalDriver {
            eprintln!("Waiting for terminal driver to exit...");
            join!(f).0.unwrap();
        }
    }

    println!();
    println!("Shutting down.");
    std::process::exit(0);
}

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
enum ThreadId {
    Pid(Pid),
    TerminalDriver,
}

fn spawn_init_proc(pid: Pid, sys: System, root_inode_id: InodeIdentifier) -> ProcessHandle {
    let sys = Arc::new(Mutex::new(sys));

    let processes = GLOBAL_PROCESS_TABLE.lock().unwrap();
    System::spawn_process(
        processes,
        sys,
        vec!["init".to_owned()],
        pid,
        Uid(0),
        (None, None),
        root_inode_id,
    )
}

fn run_init_proc(mut handle: ProcessHandle) {
    // Make init's stdin/stdout point at /dev/null. It must be the first file we open
    handle
        .sc_open("/dev/null", OpenFlags::empty(), None)
        .expect("/dev/null must exist for stdin");
    handle
        .sc_open("/dev/null", OpenFlags::empty(), None)
        .expect("/dev/null must exist for stdout");

    setup_bin_directory(&mut handle);

    let log_fd = handle
        .sc_open("/dev/log", OpenFlags::empty(), None)
        .unwrap();
    eprintln!("Opened /dev/log with fd: {}", log_fd);
    let terminal_fd = handle
        .sc_open("/dev/terminal", OpenFlags::empty(), None)
        .expect("/dev/terminal must exist to be used as shell stdin");
    let shell = handle
        .sc_spawn(
            vec!["/bin/shell".to_owned()],
            SpawnFds::Set(terminal_fd, terminal_fd),
            SpawnUid::Uid(Uid(1)),
            Some(SpawnAction::ClaimTerminal(terminal_fd)),
        )
        .unwrap();
    handle.sc_close(terminal_fd).unwrap();
    handle
        .sc_spawn(
            vec!["/bin/background".to_owned()],
            SpawnFds::Inherit,
            SpawnUid::Inherit,
            None,
        )
        .unwrap();

    handle
        .sc_write(log_fd, "Init starting...\n".as_bytes())
        .unwrap();
    loop {
        handle.handle_signals();
        let script = handle
            .sc_spawn(
                vec!["/bin/script".to_owned()],
                SpawnFds::Inherit,
                SpawnUid::Inherit,
                None,
            )
            .expect("spawn child from init");

        let script_result = loop {
            let child_result = wait_for_child(&handle, WaitPidTarget::AnyChild)
                .expect("Waiting for child")
                .expect("Should not return None as we are willing to block");

            eprintln!("Init waited and got child result: {:?}", child_result);

            let pid = child_result.0;
            if pid == shell {
                eprintln!("Main shell exited. Init will exit.");
                handle.sc_exit(0);
                return;
            }

            if pid == script {
                break child_result;
            }
        };

        handle
            .sc_write(log_fd, format!("{:?}\n", script_result).as_bytes())
            .unwrap();

        let sleep = handle
            .sc_spawn(
                vec!["/bin/sleep".to_owned()],
                SpawnFds::Inherit,
                SpawnUid::Inherit,
                None,
            )
            .expect("spawn sleep from init");
        eprintln!("Init::waitpid...");
        wait_for_child(&handle, WaitPidTarget::Pid(sleep)).unwrap();
    }
}

fn wait_for_child(
    handle: &ProcessHandle,
    target: WaitPidTarget,
) -> std::result::Result<Option<(Pid, ProcessResult)>, Ecode> {
    loop {
        match handle.sc_wait_pid(target, WaitPidOptions::Default) {
            Err(Ecode::Eintr) => continue,
            other_result => return other_result,
        }
    }
}

fn setup_bin_directory(handle: &mut ProcessHandle) {
    handle
        .sc_create("/bin", FileType::Directory, FilePermissions::new(7, 5))
        .unwrap();
    create_program_file(handle, "/bin/script", "script").unwrap();
    create_program_file(handle, "/bin/sleep", "sleep").unwrap();
    create_program_file(handle, "/bin/background", "background").unwrap();
    create_program_file(handle, "/bin/shell", "shell").unwrap();
    create_program_file(handle, "/bin/file", "file").unwrap();
    create_program_file(handle, "/bin/touch", "touch").unwrap();
    create_program_file(handle, "/bin/dump", "dump").unwrap();
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

fn run_program_proc(handle: ProcessHandle) {
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
