use crate::sys::{ProcessHandle, SpawnFds, SpawnUid, WaitPidOptions, WaitPidTarget};
use crate::util::SysResult;

pub fn run(mut handle: ProcessHandle, _args: Vec<String>) {
    let result = _run(&mut handle);

    if let Err(e) = result {
        handle.stderr(format!("Error: {}\n", e)).unwrap();
    }
}

fn _run(handle: &mut ProcessHandle) -> SysResult<()> {
    let (read_fd, write_fd) = handle.sc_pipe()?;
    eprintln!(
        "[pipedemo] created pipes with fds: {:?}",
        (read_fd, write_fd)
    );

    let echo = handle.sc_spawn(
        vec!["/bin/echo".to_owned(), "greetings".to_owned()],
        SpawnFds::Set(0, write_fd, 2),
        SpawnUid::Inherit,
        None,
    )?;
    eprintln!("[pipedemo] spawned echo: {:?}", echo);
    let cat = handle.sc_spawn(
        vec!["/bin/cat".to_owned()],
        SpawnFds::Set(read_fd, 1, 2),
        SpawnUid::Inherit,
        None,
    )?;
    eprintln!("[pipedemo] spawned cat: {:?}", cat);
    handle.sc_close(read_fd)?;
    handle.sc_close(write_fd)?;
    eprintln!("[pipedemo] Closed both pipe fds: {:?}", (read_fd, write_fd));

    let result = handle.sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::Default)?;
    eprintln!("[pipedemo] result 1: {:?}", result);
    let result = handle.sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::Default)?;
    eprintln!("[pipedemo] result 2: {:?}", result);

    Ok(())
}
