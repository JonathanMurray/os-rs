use crate::sys::{
    IoctlRequest, OpenFlags, ProcessHandle, ProcessResult, SpawnAction, SpawnFds, SpawnUid,
    WaitPidOptions, WaitPidTarget,
};
use crate::util::{FilePermissions, FileStat, FileType, Pid};
use std::collections::HashSet;
use std::fmt::Display;
use std::str::FromStr;

type Result<T> = core::result::Result<T, String>;

pub struct Shell {
    background_processes: HashSet<Pid>,
}

impl Shell {
    pub fn new() -> Self {
        Self {
            background_processes: Default::default(),
        }
    }

    pub fn handle(&mut self, handle: &mut ProcessHandle, input: String) {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if !tokens.is_empty() {
            if let Err(e) = self.handle_input(handle, tokens) {
                println!("Error: {}", e);
            }
        }
        self.check_finished_background_tasks(handle);
    }

    fn check_finished_background_tasks(&mut self, handle: &mut ProcessHandle) {
        while let Some((pid, result)) = handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::NoHang)
            .expect("Wait for background tasks")
        {
            self.background_processes.remove(&pid);
            println!("[{}] finished: {:?}", pid.0, result);
        }
    }

    fn handle_input(&mut self, handle: &mut ProcessHandle, tokens: Vec<&str>) -> Result<()> {
        let mut tokens = &tokens[..];
        let run_in_background = match tokens {
            [head @ .., "&"] => {
                tokens = head;
                true
            }
            _ => false,
        };

        let redirect = match tokens {
            [head @ .., ">", file] => {
                tokens = head;
                Some(file)
            }
            _ => None,
        };

        match redirect {
            Some(&f) => {
                let saved_stdout_fd = handle.sc_dup(1)?;
                let file_fd = handle.sc_open(
                    f,
                    OpenFlags::CREATE | OpenFlags::TRUNCATE,
                    Some(FilePermissions::ReadWrite),
                )?;
                handle.sc_dup2(file_fd, 1)?; // redirect stdout to file
                handle.sc_close(file_fd)?;

                self.execute_command(tokens, handle, run_in_background)?;

                handle.sc_dup2(saved_stdout_fd, 1)?; // restore stdout
                handle.sc_close(saved_stdout_fd)
            }
            None => self.execute_command(tokens, handle, run_in_background),
        }
    }

    fn execute_command(
        &mut self,
        tokens: &[&str],
        handle: &mut ProcessHandle,
        run_in_background: bool,
    ) -> Result<()> {
        let command = tokens[0];
        match command {
            "stat" => self.stat(tokens, handle),
            "cat" => self.cat(tokens, handle),
            "ls" => self.ls(tokens, handle),
            "ll" => self.ll(tokens, handle),
            "touch" => self.touch(tokens, handle),
            "mkdir" => self.mkdir(tokens, handle),
            "rm" => self.rm(tokens, handle),
            "mv" => self.mv(tokens, handle),
            "cd" => self.cd(tokens, handle),
            "help" => self.help(tokens, handle),
            "kill" => self.kill(tokens, handle),
            "ps" => self.ps(tokens, handle),
            "jobs" => self.jobs(tokens, handle),
            "pid" => self.pid(tokens, handle),
            "echo" => self.echo(tokens, handle),
            _ => self.dynamic_program(tokens, handle, run_in_background),
        }
    }

    fn stat(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or("missing arg")?;
        let stat = sys.sc_stat(path)?;
        stdoutln(sys, self._stat_line(stat))?;
        Ok(())
    }

    fn _stat_line(&mut self, stat: FileStat) -> String {
        let file_type = match stat.file_type {
            FileType::Regular => "file",
            FileType::Directory => "directory",
            FileType::CharacterDevice => "character device",
        }
        .to_owned();
        let permissions = match stat.permissions {
            FilePermissions::ReadOnly => "r-",
            FilePermissions::ReadWrite => "rw",
        }
        .to_owned();

        let size = format!("{} bytes", stat.size);
        format!(
            "{:>10} {:>4} {:>10} {:<13}",
            file_type,
            permissions,
            size,
            format!(
                "[{:?}:{}]",
                stat.inode_id.filesystem_id, stat.inode_id.number
            )
        )
    }

    fn cat(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        self._cat_file(path, sys)
    }

    fn _cat_file(&self, path: &str, sys: &mut ProcessHandle) -> Result<()> {
        let fd = sys.sc_open(path, OpenFlags::empty(), None)?;
        let mut buf = vec![0; 1024];
        loop {
            let n = match sys.sc_read(fd, &mut buf) {
                Ok(Some(n)) => n,
                Ok(None) => {
                    println!("WARN: Reading this would block.");
                    0
                }
                Err(e) => {
                    if let Err(e) = sys.sc_close(fd) {
                        println!("WARN: Failed to close after failing to read: {}", e);
                    }
                    return Err(e);
                }
            };
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n]);
                stdout(sys, s)?;
            } else {
                break;
            }
        }
        sys.sc_close(fd)
    }

    fn ls(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = sys.sc_stat(path)?;
        if stat.file_type == FileType::Regular {
            stdoutln(sys, path)?;
        } else {
            let dir_fd = sys.sc_open(path, OpenFlags::empty(), None).unwrap();
            let dir_entries = sys.sc_getdents(dir_fd)?;
            let names: Vec<String> = dir_entries.into_iter().map(|e| e.name).collect();
            stdoutln(sys, names.join("\t\t"))?;
            sys.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn ll(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = sys.sc_stat(path)?;
        if stat.file_type == FileType::Regular {
            let output = format!("{}{:>10}", self._stat_line(stat), path);
            stdoutln(sys, output)?;
        } else {
            let dir_fd = sys.sc_open(path, OpenFlags::empty(), None)?;
            let dir_entries = sys.sc_getdents(dir_fd)?;
            for dir_entry in dir_entries {
                let child_name = dir_entry.name;
                let child_path = format!("{}/{}", path, child_name);
                let stat = sys.sc_stat(&child_path)?;
                let output = format!("{:<44}{}", self._stat_line(stat), child_name);

                stdoutln(sys, output)?;
            }
            sys.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn touch(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        sys.sc_create(*path, FileType::Regular, FilePermissions::ReadWrite)?;
        stdoutln(sys, "File created")?;
        Ok(())
    }

    fn mkdir(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        sys.sc_create(*path, FileType::Directory, FilePermissions::ReadWrite)?;
        stdoutln(sys, "Directory created")?;
        Ok(())
    }

    /// builtin
    fn cd(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        if let Some(&path) = args.get(1) {
            sys.sc_chdir(path)
        } else {
            sys.sc_chdir("/")
        }
    }

    fn rm(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        sys.sc_unlink(path)?;
        stdoutln(sys, "File removed")?;
        Ok(())
    }

    fn mv(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        if let (Some(&src_path), Some(&dst_path)) = (args.get(1), args.get(2)) {
            sys.sc_rename(src_path, dst_path)?;
            stdoutln(sys, "File moved")?;
            Ok(())
        } else {
            Err("Error: missing arg(s)".to_owned())
        }
    }

    fn help(&mut self, _args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        self._cat_file("/README", sys)
    }

    fn kill(&mut self, args: &[&str], sys: &mut ProcessHandle) -> Result<()> {
        let pid = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        let pid = u32::from_str(*pid).map_err(|_| "Not a valid pid".to_owned())?;
        let pid = Pid(pid);
        sys.sc_kill(pid)
    }

    fn dynamic_program(
        &mut self,
        args: &[&str],
        handle: &mut ProcessHandle,
        run_in_background: bool,
    ) -> Result<()> {
        let path = format!("/bin/{}", args[0]);

        if run_in_background {
            let child_pid = handle.sc_spawn(path, SpawnFds::Inherit, SpawnUid::Inherit, None)?;
            println!("[{}] running in background...", child_pid.0);
            self.background_processes.insert(child_pid);
        } else {
            let terminal_fd = handle.sc_open("/dev/terminal", OpenFlags::empty(), None)?;
            let child_pid = handle.sc_spawn(
                path,
                SpawnFds::Inherit,
                SpawnUid::Inherit,
                Some(SpawnAction::ClaimTerminal(terminal_fd)),
            )?;

            let result =
                handle.sc_wait_pid(WaitPidTarget::Pid(child_pid), WaitPidOptions::Default)?;
            match result.unwrap() {
                (_, ProcessResult::ExitCode(0)) => {}
                (child_pid, bad_result) => {
                    println!("[{}]: {:?}", child_pid.0, bad_result);
                }
            }
            let pid = handle.sc_getpid();
            handle.sc_ioctl(terminal_fd, IoctlRequest::SetTerminalForegroundProcess(pid))?;
            handle.sc_close(terminal_fd)?;
        }

        Ok(())
    }

    fn ps(&mut self, _args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        let fd = handle.sc_open("/proc/status", OpenFlags::empty(), None)?;

        //TODO read arbitrarily large file
        let mut buf = vec![0; 2048];
        //TODO if reading fails, we leak the FD
        let n_read = handle
            .sc_read(fd, &mut buf)?
            .expect("shouldn't need to block on proc");

        assert!(
            n_read < buf.len(),
            "Filled whole buffer when readingproc/status file: {:?}",
            String::from_utf8_lossy(&buf[..])
        );

        let content = String::from_utf8_lossy(&buf[..n_read]);
        let mut lines = content.lines();

        lines.next(); // uptime
        lines.next(); // number of processes
        let output = format!(
            "{:>4}{:>4}{:>8}  {:<10}{:>4}  NAME",
            "UID", "PID", "PARENT", "STATE", "FDs"
        );
        stdoutln(handle, output)?;
        for line in lines {
            let tokens: Vec<&str> = line.split(' ').collect();
            let output = format!(
                "{:>4}{:>4}{:>8}  {:<10}{:>4}  {}",
                tokens[4], tokens[0], tokens[1], tokens[3], tokens[5], tokens[2]
            );
            stdoutln(handle, output)?;
        }

        handle.sc_close(fd)?;

        Ok(())
    }

    /// builtin
    fn jobs(&mut self, _args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        self.check_finished_background_tasks(handle);

        if !self.background_processes.is_empty() {
            for pid in self.background_processes.iter() {
                let output = format!("[{}] Running", pid.0);
                stdoutln(handle, output)?;
            }
        }
        Ok(())
    }

    fn pid(&mut self, _args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        let pid = handle.sc_getpid();
        stdoutln(handle, pid.0)?;
        Ok(())
    }

    fn echo(&mut self, args: &[&str], handle: &mut ProcessHandle) -> Result<()> {
        let output = &args[1..].join(" ");
        stdoutln(handle, output)?;
        Ok(())
    }
}

fn stdoutln(handle: &mut ProcessHandle, s: impl Display) -> Result<()> {
    let output = format!("{}\n", s);
    stdout(handle, output)
}

fn stdout(handle: &mut ProcessHandle, s: impl Display) -> Result<()> {
    let output = format!("{}", s);
    let n_written = handle.sc_write(1, output.as_bytes())?;
    assert_eq!(
        n_written,
        output.len(),
        "We didn't write all the output to stdout"
    );
    Ok(())
}
