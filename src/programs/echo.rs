use crate::sys::ProcessHandle;
use crate::util::SysResult;

pub fn run(mut handle: ProcessHandle, args: Vec<String>) {
    if let Err(e) = _run(&mut handle, args) {
        handle.stderr(format!("Error: {}\n", e)).unwrap();
    }
}

pub fn _run(handle: &mut ProcessHandle, args: Vec<String>) -> SysResult<()> {
    let output = &args[1..].join(" ");
    handle.stdout(format!("{}\n", output))?;
    Ok(())
}
