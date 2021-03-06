use crate::sys::ProcessHandle;
use crate::util::Ecode;

pub fn run(mut handle: ProcessHandle, args: Vec<String>) {
    if let Err(e) = _run(&mut handle, &args) {
        handle
            .stderr(format!("{} error: {}\n", args[0], e))
            .unwrap();
    }
}

pub fn _run(handle: &mut ProcessHandle, args: &[String]) -> Result<(), String> {
    if args.len() != 1 {
        return Err("Unrecognized args".to_owned());
    }
    let mut buf = [0; 1024];
    let mut count = 0;
    loop {
        match handle.sc_read(0, &mut buf) {
            Ok(0) => break,
            Ok(n) => count += n,
            Err(Ecode::Eagain) => return Err("Reading would block".to_owned()),
            Err(e) => return Err(e.into()),
        }
    }
    handle.stdout(format!("{}\n", count))?;
    Ok(())
}
