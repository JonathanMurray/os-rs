use crate::programs::file_helpers::FileReader;
use crate::sys::{
    IoctlRequest, OpenFlags, ProcessHandle, ProcessResult, Signal, SignalHandler, SpawnAction,
    SpawnFds, SpawnUid, WaitPidOptions, WaitPidTarget,
};
use crate::util::{FilePermissions, FileStat, FileType, Pid};

use std::collections::HashSet;
use std::fmt::Display;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::Duration;

type Result<T> = core::result::Result<T, String>;

pub struct ShellProcess {
    background_processes: HashSet<Pid>,
    handle: Arc<ProcessHandle>,
    has_requested_exit: bool,
}

#[derive(Debug)]
struct SigintHandler(Weak<ProcessHandle>);

impl SignalHandler for SigintHandler {
    fn handle(&self, signal: Signal) {
        if let Some(handle) = self.0.upgrade() {
            handle.stdout("\n").unwrap();
            ShellProcess::print_prompt(&handle);
        } else {
            panic!(
                "WARN: Signal handler was invoked after the shell had been dropped ({:?})",
                signal
            );
        }
    }
}

impl ShellProcess {
    pub fn new(handle: ProcessHandle) -> Self {
        Self {
            background_processes: Default::default(),
            handle: Arc::new(handle),
            has_requested_exit: false,
        }
    }

    pub fn run(mut self) {
        // We hand over a weak clone of the process handle to our handler function.
        // The handler function should never be used after the shell has exited.
        let weak_process_handle = Arc::downgrade(&self.handle);
        self.handle.sc_sigaction(
            Signal::Interrupt,
            Box::new(SigintHandler(weak_process_handle)),
        );

        self.handle.stdout("Welcome!\n").unwrap();
        ShellProcess::print_prompt(&self.handle);

        let mut buf = [0; 1024];
        let mut buffered_lines: Vec<String> = Vec::new();
        let mut current_line: Vec<u8> = Vec::new();
        while !self.has_requested_exit {
            let n = loop {
                self.handle.handle_signals();

                match self.handle.sc_read(0, &mut buf) {
                    Ok(Some(n)) => break n,
                    Ok(None) => {
                        // Would need to block to get input
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        println!("WARN: Shell failed to read stdin: {}", e);
                        return self.do_exit(1);
                    }
                };
            };

            if n == 0 {
                //EOF
                break;
            }

            // Try to build up lines from the data we received
            let mut left = 0;
            for right in 0..n {
                if buf[right] == b'\n' {
                    current_line.extend(&buf[left..right + 1]);
                    left = right + 1;
                    buffered_lines.push(String::from_utf8(current_line).expect("UTF8 stdin line"));
                    current_line = Vec::new();
                } else if right == n - 1 {
                    current_line.extend(&buf[left..right + 1]);
                }
            }

            // Handle any completed lines
            for line in buffered_lines {
                eprintln!("DEBUG: COMPLETED SHELL LINE: '{}'", line);
                self.handle_input(line.to_owned());
                ShellProcess::print_prompt(&self.handle);
            }
            buffered_lines = Vec::new();
        }

        self.handle.stdout("Bye!\n").unwrap();
        self.do_exit(0);
    }

    fn do_exit(self, status: u32) {
        let handle = Arc::try_unwrap(self.handle)
            .expect("There should be only one strong reference (owned by this shell)");
        handle.sc_exit(status);
    }

    fn print_prompt(handle: &ProcessHandle) {
        let current_dir_name = handle
            .sc_get_current_dir_name()
            .expect("Must have valid cwd");
        handle
            .stdout(&format!("{}$ ", current_dir_name.as_str()))
            .expect("Write to stdout");
    }

    fn handle_input(&mut self, input: String) {
        let tokens: Vec<&str> = input.split_whitespace().collect();
        if !tokens.is_empty() {
            if let Err(e) = self.handle_tokenized_input(tokens) {
                self.handle.stdout(format!("Error: {}\n", e)).unwrap();
            }
        }
        self.check_finished_background_tasks();
    }

    fn check_finished_background_tasks(&mut self) {
        while let Some((pid, result)) = self
            .handle
            .sc_wait_pid(WaitPidTarget::AnyChild, WaitPidOptions::NoHang)
            .expect("Wait for background tasks")
        {
            self.background_processes.remove(&pid);
            self.handle
                .stdout(format!("[{}] finished: {:?}\n", pid.0, result))
                .unwrap();
        }
    }

    fn handle_tokenized_input(&mut self, tokens: Vec<&str>) -> Result<()> {
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
                let saved_stdout_fd = self.handle.sc_dup(1)?;
                let file_fd = self.handle.sc_open(
                    f,
                    OpenFlags::CREATE | OpenFlags::TRUNCATE,
                    Some(FilePermissions::new(7, 7)),
                )?;
                self.handle.sc_dup2(file_fd, 1)?; // redirect stdout to file
                self.handle.sc_close(file_fd)?;

                self.execute_command(tokens, run_in_background)?;

                self.handle.sc_dup2(saved_stdout_fd, 1)?; // restore stdout
                self.handle.sc_close(saved_stdout_fd)
            }
            None => self.execute_command(tokens, run_in_background),
        }
    }

    fn execute_command(&mut self, tokens: &[&str], run_in_background: bool) -> Result<()> {
        let command = tokens[0];
        match command {
            "stat" => self.stat(tokens),
            "cat" => self.cat(tokens),
            "ls" => self.ls(tokens),
            "ll" => self.ll(tokens),
            "mkdir" => self.mkdir(tokens),
            "rm" => self.rm(tokens),
            "mv" => self.mv(tokens),
            "cd" => self.cd(tokens),
            "help" => self.help(tokens),
            "kill" => self.kill(tokens),
            "ps" => self.ps(tokens),
            "jobs" => self.jobs(tokens),
            "pid" => self.pid(tokens),
            "echo" => self.echo(tokens),
            "exit" => self.exit(tokens),
            "crash" => self.crash(tokens),
            _ => self.dynamic_program(tokens, run_in_background),
        }
    }

    fn stat(&mut self, args: &[&str]) -> Result<()> {
        let path = args.get(1).ok_or("missing arg")?;
        let stat = self.handle.sc_stat(path)?;
        let output = self._stat_line(stat);
        self.stdoutln(output)?;
        Ok(())
    }

    fn _stat_line(&mut self, stat: FileStat) -> String {
        let file_type = match stat.file_type {
            FileType::Regular => "file",
            FileType::Directory => "directory",
            FileType::CharacterDevice => "device",
        }
        .to_owned();
        let size = format!("{} bytes", stat.size);
        format!(
            "{:>7} {:>10}  {} {:>10} {:<13}",
            format!("{:?}", stat.user_id),
            file_type,
            stat.permissions,
            size,
            format!(
                "[{:?}:{}]",
                stat.inode_id.filesystem_id, stat.inode_id.number
            )
        )
    }

    fn cat(&mut self, args: &[&str]) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        self._cat_file(path)
    }

    fn _cat_file(&mut self, path: &str) -> Result<()> {
        let fd = self.handle.sc_open(path, OpenFlags::empty(), None)?;
        let count = 256;
        loop {
            match self.handle.sc_sendfile(1, fd, count)? {
                Some(0) => break, //EOF
                None => {
                    self.stdoutln("Error: Reading would block!")?;
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn ls(&mut self, args: &[&str]) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = self.handle.sc_stat(path)?;
        if stat.file_type == FileType::Regular {
            self.stdoutln(path)?;
        } else {
            let dir_fd = self.handle.sc_open(path, OpenFlags::empty(), None).unwrap();
            let dir_entries = self.handle.sc_getdents(dir_fd)?;
            let names: Vec<String> = dir_entries.into_iter().map(|e| e.name).collect();
            self.stdoutln(names.join("\t\t"))?;
            self.handle.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn ll(&mut self, args: &[&str]) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = self.handle.sc_stat(path)?;
        if stat.file_type == FileType::Regular {
            let output = format!("{}{:>10}", self._stat_line(stat), path);
            self.stdoutln(output)?;
        } else {
            let dir_fd = self.handle.sc_open(path, OpenFlags::empty(), None)?;
            //TODO We leak fd if getdents fails. Move this to a util class (FileReader)?
            let dir_entries = self.handle.sc_getdents(dir_fd)?;
            for dir_entry in dir_entries {
                let child_name = dir_entry.name;
                let child_path = format!("{}/{}", path, child_name);
                let stat = self.handle.sc_stat(&child_path)?;
                let output = format!("{:<44}{}", self._stat_line(stat), child_name);

                self.stdoutln(output)?;
            }
            self.handle.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn mkdir(&mut self, args: &[&str]) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        self.handle
            .sc_create(*path, FileType::Directory, FilePermissions::new(7, 7))?;
        self.stdoutln("Directory created")?;
        Ok(())
    }

    /// builtin
    fn cd(&mut self, args: &[&str]) -> Result<()> {
        if let Some(&path) = args.get(1) {
            self.handle.sc_chdir(path)
        } else {
            self.handle.sc_chdir("/")
        }
    }

    fn rm(&mut self, args: &[&str]) -> Result<()> {
        let path = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        self.handle.sc_unlink(path)?;
        self.stdoutln("File removed")?;
        Ok(())
    }

    fn mv(&mut self, args: &[&str]) -> Result<()> {
        if let (Some(&src_path), Some(&dst_path)) = (args.get(1), args.get(2)) {
            self.handle.sc_rename(src_path, dst_path)?;
            self.stdoutln("File moved")?;
            Ok(())
        } else {
            Err("Error: missing arg(s)".to_owned())
        }
    }

    fn help(&mut self, _args: &[&str]) -> Result<()> {
        self._cat_file("/README")
    }

    fn kill(&mut self, args: &[&str]) -> Result<()> {
        let pid = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        let pid = u32::from_str(*pid).map_err(|_| "Not a valid pid".to_owned())?;
        let pid = Pid(pid);
        self.handle.sc_kill(pid, Signal::Kill)
    }

    fn dynamic_program(&mut self, args: &[&str], run_in_background: bool) -> Result<()> {
        let mut args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        args[0] = format!("/bin/{}", args[0]);
        if run_in_background {
            let child_pid =
                self.handle
                    .sc_spawn(args, SpawnFds::Inherit, SpawnUid::Inherit, None)?;
            self.handle
                .stdout(format!("[{}] running in background...\n", child_pid.0))
                .unwrap();
            self.background_processes.insert(child_pid);
        } else {
            let terminal_fd = self
                .handle
                .sc_open("/dev/terminal", OpenFlags::empty(), None)?;
            let child_pid = self.handle.sc_spawn(
                args,
                SpawnFds::Inherit,
                SpawnUid::Inherit,
                Some(SpawnAction::ClaimTerminal(terminal_fd)),
            )?;

            let result = self
                .handle
                .sc_wait_pid(WaitPidTarget::Pid(child_pid), WaitPidOptions::Default)?;
            match result.unwrap() {
                (_, ProcessResult::ExitCode(0)) => {}
                (child_pid, bad_result) => {
                    self.handle
                        .stdout(format!("[{}]: {:?}\n", child_pid.0, bad_result))
                        .unwrap();
                }
            }
            let pid = self.handle.sc_getpid();
            self.handle
                .sc_ioctl(terminal_fd, IoctlRequest::SetTerminalForegroundProcess(pid))?;
            self.handle.sc_close(terminal_fd)?;
        }

        Ok(())
    }

    fn ps(&mut self, _args: &[&str]) -> Result<()> {
        let mut f = FileReader::open(&self.handle, "/proc/status")?;
        let content = f.read_to_string()?;
        let mut lines = content.lines();
        f.close();

        lines.next(); // uptime
        lines.next(); // number of processes
        let output = format!(
            "{:>4}{:>4}{:>8}  {:<10}{:>4}  NAME",
            "UID", "PID", "PARENT", "STATE", "FDs"
        );
        self.stdoutln(output)?;
        for line in lines {
            let tokens: Vec<&str> = line.split(' ').collect();
            let output = format!(
                "{:>4}{:>4}{:>8}  {:<10}{:>4}  {}",
                tokens[4], tokens[0], tokens[1], tokens[3], tokens[5], tokens[2]
            );
            self.stdoutln(output)?;
        }

        Ok(())
    }

    /// builtin
    fn jobs(&mut self, _args: &[&str]) -> Result<()> {
        self.check_finished_background_tasks();

        let messages: Vec<String> = self
            .background_processes
            .iter()
            .map(|pid| format!("[{}] Running", pid.0))
            .collect();

        for msg in messages {
            self.stdoutln(msg)?;
        }
        Ok(())
    }

    fn pid(&mut self, _args: &[&str]) -> Result<()> {
        let pid = self.handle.sc_getpid();
        self.stdoutln(pid.0)?;
        Ok(())
    }

    fn echo(&mut self, args: &[&str]) -> Result<()> {
        let output = &args[1..].join(" ");
        self.stdoutln(output)?;
        Ok(())
    }

    fn exit(&mut self, _args: &[&str]) -> Result<()> {
        self.has_requested_exit = true;
        Ok(())
    }

    fn crash(&mut self, args: &[&str]) -> Result<()> {
        panic!("Intentional crash: {:?}", args);
    }

    fn stdoutln(&mut self, s: impl Display) -> Result<()> {
        let output = format!("{}\n", s);
        self.handle.stdout(output)
    }
}
