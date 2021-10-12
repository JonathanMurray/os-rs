mod filesystems;
mod programs;
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

use crate::filesystems::devfs::DevFilesystem;
use crate::sys::{
    OpenFlags, ProcessHandle, ProcessResult, ProcessWasKilledPanic, SpawnAction, SpawnFds,
    SpawnUid, System, WaitPidOptions, WaitPidTarget, GLOBAL_PROCESS_TABLE,
};
use crate::util::{Ecode, FilePermissions, FileType, InodeIdentifier, Pid, Uid};
use crate::vfs::VirtualFilesystemSwitch;

#[tokio::main]
pub async fn main() {
    println!("Operating System initializing...");

    eprintln!("--------------------------------");

    let mut vfs = VirtualFilesystemSwitch::new();
    let root_inode_id = vfs.root_inode_id();
    let terminal_out = Arc::new(Mutex::new(Default::default()));
    let (devfs, terminal_in) = DevFilesystem::new(root_inode_id, Arc::clone(&terminal_out));
    vfs.mount_filesystem("dev".to_owned(), devfs);
    let should_terminal_thread_exit = Arc::new(AtomicBool::new(false));
    let terminal_driver_fut = {
        let should_exit = Arc::clone(&should_terminal_thread_exit);
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

    let mut tokio_threads = vec![
        (ThreadId::Pid(init_pid), init_fut),
        (ThreadId::TerminalDriver, terminal_driver_fut),
    ];

    loop {
        let mut finished_threads = HashSet::new();
        let mut should_shut_down = false;
        for (thread_id, future) in tokio_threads.iter_mut() {
            match poll!(future) {
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
        tokio_threads.retain(|(pid, _)| !finished_threads.contains(pid));
        if should_shut_down {
            break;
        }

        // is this sleep needed?
        std::thread::sleep(Duration::from_millis(5));

        {
            let mut spawn_queue = sys::GLOBAL_PROCESS_SPAWN_QUEUE.lock().unwrap();
            if let Some(new_handle) = spawn_queue.pop_back() {
                let pid = new_handle.pid();
                let f = tokio::task::spawn_blocking(move || programs::run_program(new_handle));
                tokio_threads.push((ThreadId::Pid(pid), f.fuse()));
            }
        }
    }

    eprintln!("Exited loop in main method");
    should_terminal_thread_exit.store(true, Ordering::Relaxed);

    for (id, future) in tokio_threads {
        // Wait for terminal driver to exit, so that we don't
        // exit the program with a messed up terminal state
        if id == ThreadId::TerminalDriver {
            eprintln!("Waiting for terminal driver to exit...");
            join!(future).0.unwrap();
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
        (None, None, None),
        root_inode_id,
    )
}

fn run_init_proc(mut handle: ProcessHandle) {
    // Make init's stdin/stdout point at /dev/null. It must be the first file we open
    handle
        .sc_open("/dev/null", OpenFlags::READ_ONLY, None)
        .expect("/dev/null must exist for stdin");
    handle
        .sc_open("/dev/null", OpenFlags::WRITE_ONLY, None)
        .expect("/dev/null must exist for stdout");

    handle
        .sc_create("/bin", FileType::Directory, FilePermissions::new(7, 5))
        .unwrap();
    programs::add_program_files_to_bin_dir(&mut handle);

    let log_fd = handle
        .sc_open("/dev/log", OpenFlags::WRITE_ONLY, None)
        .unwrap();
    eprintln!("Opened /dev/log with fd: {}", log_fd);
    let terminal_fd = handle
        .sc_open("/dev/terminal", OpenFlags::READ_WRITE, None)
        .expect("/dev/terminal must exist to be used as shell stdin");
    let shell = handle
        .sc_spawn(
            vec!["/bin/shell".to_owned()],
            SpawnFds::Set(terminal_fd, terminal_fd, terminal_fd),
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

    let run_background_scripts = false;

    loop {
        handle.handle_signals();

        if run_background_scripts {
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
        } else {
            loop {
                let child_result = wait_for_child(&handle, WaitPidTarget::AnyChild)
                    .expect("Waiting for child")
                    .expect("Should not return None as we are willing to block");

                let pid = child_result.0;
                if pid == shell {
                    eprintln!("Main shell exited. Init will exit.");
                    handle.sc_exit(0);
                    return;
                }
            }
        }

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
