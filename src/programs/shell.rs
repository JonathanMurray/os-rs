use crate::programs::file_helpers::FileReader;
use crate::sys::{
    IoctlRequest, OpenFlags, ProcessHandle, ProcessResult, Signal, SignalHandler, SpawnAction,
    SpawnFds, SpawnUid, WaitPidOptions, WaitPidTarget,
};
use crate::util::{Ecode, Fd, FilePermissions, FileStat, FileType, Pid, SysResult};

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
                "Signal handler was invoked after the shell had been dropped ({:?})",
                signal
            );
        }
    }
}

pub fn run(handle: ProcessHandle, args: Vec<String>) {
    let shell = ShellProcess::new(handle);
    shell.run(args)
}

impl ShellProcess {
    fn new(handle: ProcessHandle) -> Self {
        Self {
            background_processes: Default::default(),
            handle: Arc::new(handle),
            has_requested_exit: false,
        }
    }

    fn run(mut self, args: Vec<String>) {
        if args.len() > 1 {
            // The shell was called like "shell touch new_file"
            let command = &args[1];
            if self.is_builtin(command) {
                let args: Vec<&str> = args[1..].iter().map(|s| &s[..]).collect();
                match self.run_builtin(&args[..], None) {
                    Ok(_) => return self.do_exit(0),
                    Err(e) => {
                        self.handle.stderr(format!("shell error: {}\n", e)).unwrap();
                        return self.do_exit(1);
                    }
                }
            } else {
                self.handle.stderr("shell error: invalid args\n").unwrap();
                return self.do_exit(1);
            }
        }

        // We hand over a weak clone of the process handle to our handler function.
        // The handler function should never be used after the shell has exited.
        let weak_process_handle = Arc::downgrade(&self.handle);
        self.handle.sc_sigaction(
            Signal::Interrupt,
            Box::new(SigintHandler(weak_process_handle)),
        );

        //self.handle.stdout("Welcome!\n").unwrap();
        ShellProcess::print_prompt(&self.handle);

        let mut buf = [0; 1024];
        let mut buffered_lines: Vec<String> = Vec::new();
        let mut current_line: Vec<u8> = Vec::new();
        while !self.has_requested_exit {
            let n = loop {
                self.handle.handle_signals();

                match self.handle.sc_read(0, &mut buf) {
                    Ok(n) => break n,
                    Err(Ecode::Eagain) => {
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
                eprintln!("[shell] COMPLETED SHELL LINE: '{}'", line);

                let tokens: Vec<&str> = line.split_whitespace().collect();
                if !tokens.is_empty() {
                    self.handle_input(tokens);
                }

                self.check_finished_background_tasks();

                ShellProcess::print_prompt(&self.handle);
            }
            buffered_lines = Vec::new();
        }

        //self.handle.stdout("Bye!\n").unwrap();
        self.do_exit(0);
    }

    fn do_exit(self, status: u32) {
        let handle = Arc::try_unwrap(self.handle)
            .expect("There should be only one strong reference (owned by this shell)");
        handle.sc_exit(status);
    }

    fn print_prompt(handle: &ProcessHandle) {
        let current_dir_name = handle.get_current_dir_name().expect("Must have valid cwd");
        handle
            .stdout(&format!("{}$ ", current_dir_name.as_str()))
            .expect("Write to stdout");
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

    fn handle_input(&mut self, tokens: Vec<&str>) {
        let mut tokens = &tokens[..];
        let run_in_background = self.parse_background_token(&mut tokens);

        let pipeline_parts: Vec<&[&str]> = tokens.split(|x| *x == "|").collect();

        // 1. The simple case: we run a builtin command in the foreground
        if pipeline_parts.len() == 1 {
            let command = tokens[0];
            if self.is_builtin(command) && !run_in_background {
                let redirect = self.parse_redirect_token(&mut tokens);
                if let Err(e) = self.run_builtin(tokens, redirect) {
                    self.handle.stderr(format!("shell error: {}\n", e)).unwrap();
                }
                return;
            }
        }

        // 2. The more implicated case: involving pipes/bg/programs

        let mut read_end_of_last_pipe: Option<Fd> = None;
        let mut pids: Vec<Pid> = vec![];
        let num_pipeline_parts = pipeline_parts.len();

        for (i, mut tokens) in pipeline_parts.into_iter().enumerate() {
            eprintln!("[pipeline] handling pipeline part: {:?}", tokens);
            let redirect = self.parse_redirect_token(&mut tokens);

            let mut piped_stdin = None;
            let mut piped_stdout = None;

            if num_pipeline_parts > 1 {
                if i == 0 {
                    let (pipe_read, pipe_write) = self.handle.sc_pipe().unwrap();
                    piped_stdout = Some(pipe_write);
                    read_end_of_last_pipe = Some(pipe_read);
                } else if i < num_pipeline_parts - 1 {
                    let (pipe_read, pipe_write) = self.handle.sc_pipe().unwrap();
                    piped_stdin = Some(read_end_of_last_pipe.unwrap());
                    piped_stdout = Some(pipe_write);
                    read_end_of_last_pipe = Some(pipe_read);
                } else {
                    piped_stdin = Some(read_end_of_last_pipe.unwrap());
                }
            }

            // TODO:
            // BUG: Shell can be run reading from a pipe
            // (e.g. "cat | shell"), in which case it is not
            // correct to claim the terminal fg here.
            // The consequence of this bug is that we "reclaim" the
            // terminal after the subprocess has finished, even
            // though our stdin points to a pipe. "cat" which has
            // a stdin pointing to the terminal device now cannot
            // read from the terminal anymore.

            let claim_terminal_fg = i == 0 && !run_in_background;
            let command = tokens[0];
            let builtin = self.is_builtin(command);
            let subprocess_result = self.start_process(
                tokens,
                builtin,
                piped_stdin.unwrap_or(0),
                piped_stdout.unwrap_or(1),
                claim_terminal_fg,
                redirect,
            );

            // Close pipe fd's, so that we don't leak resources
            if let Some(piped_stdout) = piped_stdout {
                self.handle.sc_close(piped_stdout).unwrap();
            }
            if let Some(piped_stdin) = piped_stdin {
                self.handle.sc_close(piped_stdin).unwrap();
            }

            match subprocess_result {
                Err(e) => {
                    self.stdoutln(format!("Failed to start {}: {}", command, e))
                        .unwrap();
                    self.reclaim_terminal();
                    return;
                    // TODO: should we kill any other procs that were spawned?
                }
                Ok(pid) => {
                    pids.push(pid);
                }
            }
        }

        if run_in_background {
            self.background_processes.extend(&pids);
        } else {
            eprintln!("[pipeline] Waiting for pids: {:?}", pids);
            while !pids.is_empty() {
                let (child_pid, child_result) = self
                    .wait_for_child(WaitPidTarget::AnyChild)
                    .unwrap()
                    .unwrap();

                // TODO We can accidentally wait for a background pid here.
                // Should we be passing in a "process group id" instead
                // that refers to all the tasks of this pipeline?
                self.background_processes.remove(&child_pid);

                eprintln!("[pipeline] Child finished: {:?}", child_pid);
                pids.retain(|p| *p != child_pid);
                match child_result {
                    ProcessResult::ExitCode(0) => {}
                    bad_result => {
                        self.handle
                            .stdout(format!("[{}]: {:?}\n", child_pid.0, bad_result))
                            .unwrap();
                    }
                }
            }

            self.reclaim_terminal();
        }
    }

    fn parse_background_token(&mut self, tokens: &mut &[&str]) -> bool {
        match tokens {
            [head @ .., "&"] => {
                *tokens = head;
                true
            }
            _ => false,
        }
    }

    fn parse_redirect_token(&mut self, tokens: &mut &[&str]) -> Option<String> {
        match tokens {
            [head @ .., ">", file] => {
                *tokens = head;
                Some(file.to_string())
            }
            _ => None,
        }
    }

    fn start_process(
        &mut self,
        tokens: &[&str],
        builtin: bool,
        stdin: Fd,
        mut stdout: Fd,
        claim_terminal_fg: bool,
        redirect: Option<String>,
    ) -> SysResult<Pid> {
        let mut redirect_fd = None;
        if let Some(path) = redirect {
            let fd = self.open_for_redirect(&path)?;
            stdout = fd;
            redirect_fd = Some(fd);
        }

        let stderr = 2;
        let fds = SpawnFds::Set(stdin, stdout, stderr);

        let args = if builtin {
            let mut args = vec!["/bin/shell".to_owned()];
            args.extend(tokens.iter().map(|s| s.to_string()));
            args
        } else {
            let mut args: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
            args[0] = format!("/bin/{}", args[0]);
            args
        };

        let result = self.spawn_process(args, fds, claim_terminal_fg);

        if let Some(fd) = redirect_fd {
            self.handle.sc_close(fd)?;
        }

        result
    }

    fn open_for_redirect(&mut self, path: &str) -> SysResult<Fd> {
        self.handle.sc_open(
            path,
            OpenFlags::WRITE_ONLY | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            Some(FilePermissions::new(7, 7)),
        )
    }

    fn reclaim_terminal(&mut self) {
        let terminal_fd = self.open_terminal_device();
        let pid = self.handle.sc_getpid();

        self.handle
            .sc_ioctl(terminal_fd, IoctlRequest::SetTerminalForegroundProcess(pid))
            .unwrap();
        self.handle.sc_close(terminal_fd).unwrap();
    }

    fn open_terminal_device(&mut self) -> Fd {
        self.handle
            .sc_open("/dev/terminal", OpenFlags::READ_WRITE, None)
            .unwrap()
    }

    fn spawn_process(
        &mut self,
        args: Vec<String>,
        spawn_fds: SpawnFds,
        claim_terminal_fg: bool,
    ) -> SysResult<Pid> {
        if claim_terminal_fg {
            let terminal_fd = self.open_terminal_device();
            let pid = self.handle.sc_spawn(
                args,
                spawn_fds,
                SpawnUid::Inherit,
                Some(SpawnAction::ClaimTerminal(terminal_fd)),
            )?;

            self.handle.sc_close(terminal_fd).unwrap();
            Ok(pid)
        } else {
            self.handle
                .sc_spawn(args, spawn_fds, SpawnUid::Inherit, None)
        }
    }

    // --------------------------------------------------------------
    //        BUILTINS BELOW
    // --------------------------------------------------------------

    fn is_builtin(&self, command: &str) -> bool {
        matches!(
            command,
            "stat"
                | "ls"
                | "ll"
                | "mkdir"
                | "rm"
                | "mv"
                | "cd"
                | "kill"
                | "ps"
                | "jobs"
                | "pid"
                | "exit"
                | "crash"
        )
    }

    fn run_builtin(&mut self, tokens: &[&str], redirect: Option<String>) -> SysResult<()> {
        let old_stdout = if let Some(path) = redirect {
            let fd = self.open_for_redirect(&path)?;
            let old_stdout = self.handle.sc_dup(1).unwrap();
            self.handle.sc_dup2(fd, 1).unwrap();
            Some(old_stdout)
        } else {
            None
        };

        let command = tokens[0];
        let result = match command {
            "stat" => self.stat(tokens),
            "ls" => self.ls(tokens),
            "ll" => self.ll(tokens),
            "mkdir" => self.mkdir(tokens),
            "rm" => self.rm(tokens),
            "mv" => self.mv(tokens),
            "cd" => self.cd(tokens),
            "kill" => self.kill(tokens),
            "ps" => self.ps(tokens),
            "jobs" => self.jobs(tokens),
            "pid" => self.pid(tokens),
            "exit" => self.exit(tokens),
            "crash" => self.crash(tokens),
            _ => panic!("Unhandled builtin"),
        };

        if let Some(old_stdout) = old_stdout {
            self.handle.sc_close(1).unwrap();
            self.handle.sc_dup2(old_stdout, 1).unwrap();
            self.handle.sc_close(old_stdout).unwrap();
        }

        result.map_err(Ecode::Custom)
    }

    fn stat(&mut self, args: &[&str]) -> Result<()> {
        let path = args.get(1).ok_or("missing arg")?;
        let stat = self.handle.sc_stat(path).map_err(|e| format!("{}", e))?;
        let output = self._stat_line(stat);
        self.stdoutln(output)?;
        Ok(())
    }

    fn _stat_line(&mut self, stat: FileStat) -> String {
        let file_type = match stat.file_type {
            FileType::Regular => "file",
            FileType::Directory => "directory",
            FileType::CharacterDevice => "device",
            FileType::Pipe => "pipe",
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

    fn ls(&mut self, args: &[&str]) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = self.handle.sc_stat(path).map_err(|e| format!("{}", e))?;
        if stat.file_type == FileType::Regular {
            self.stdoutln(path)?;
        } else {
            let dir_fd = self
                .handle
                .sc_open(path, OpenFlags::READ_ONLY, None)
                .unwrap();
            let dir_entries = self.handle.sc_getdents(dir_fd)?;
            let names: Vec<String> = dir_entries.into_iter().map(|e| e.name).collect();
            self.stdoutln(names.join("\t\t"))?;
            self.handle.sc_close(dir_fd)?;
        }
        Ok(())
    }

    fn ll(&mut self, args: &[&str]) -> Result<()> {
        let path: &str = args.get(1).unwrap_or(&".");
        let stat = self.handle.sc_stat(path).map_err(|e| format!("{}", e))?;
        if stat.file_type == FileType::Regular {
            let output = format!("{}{:>10}", self._stat_line(stat), path);
            self.stdoutln(output)?;
        } else {
            let dir_fd = self.handle.sc_open(path, OpenFlags::READ_ONLY, None)?;
            //TODO We leak fd if getdents fails. Move this to a util class (FileReader)?
            let dir_entries = self.handle.sc_getdents(dir_fd)?;
            for dir_entry in dir_entries {
                let child_name = dir_entry.name;
                let child_path = format!("{}/{}", path, child_name);
                let stat = self
                    .handle
                    .sc_stat(&child_path)
                    .map_err(|e| format!("{}", e))?;
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
            self.handle.sc_chdir(path).map_err(|e| format!("{}", e))
        } else {
            self.handle.sc_chdir("/").map_err(|e| format!("{}", e))
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
            Err("missing arg(s)".to_owned())
        }
    }

    fn kill(&mut self, args: &[&str]) -> Result<()> {
        let pid = args.get(1).ok_or_else(|| "missing arg".to_owned())?;
        let pid = u32::from_str(*pid).map_err(|_| "Invalid non-integer process ID".to_owned())?;
        let pid = Pid(pid);
        self.handle.sc_kill(pid, Signal::Kill)?;
        Ok(())
    }

    fn ps(&mut self, _args: &[&str]) -> Result<()> {
        let mut f = FileReader::open(&self.handle, "/proc/status")?;
        let content = f
            .read_to_string()
            .map_err(|e| format!("Failed to read proc file: {}", e))?;
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

    fn exit(&mut self, _args: &[&str]) -> Result<()> {
        self.has_requested_exit = true;
        Ok(())
    }

    fn crash(&mut self, args: &[&str]) -> Result<()> {
        panic!("Intentional crash: {:?}", args);
    }

    fn stdoutln(&mut self, s: impl Display) -> Result<()> {
        let output = format!("{}\n", s);
        self.handle.stdout(output)?;
        Ok(())
    }

    fn wait_for_child(&mut self, target: WaitPidTarget) -> SysResult<Option<(Pid, ProcessResult)>> {
        loop {
            match self.handle.sc_wait_pid(target, WaitPidOptions::Default) {
                Err(Ecode::Eintr) => continue,
                other_result => return other_result,
            }
        }
    }
}
