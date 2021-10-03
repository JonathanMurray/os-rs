use crate::devfs::TerminalInputFeeder;

use std::io;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use termion::event::Key;
use termion::input::TermRead;
use termion::raw::{IntoRawMode, RawTerminal};
use termion::{clear, cursor};

pub fn run(should_exit: Arc<AtomicBool>, input: TerminalInputFeeder, output: Arc<Mutex<Vec<u8>>>) {
    TerminalDriver::new(should_exit, input, output).run()
}

struct TerminalDriver {
    line: CurrentLine,
    exit_signal: Arc<AtomicBool>,
    to_kernel: TerminalInputFeeder,
    from_kernel: Arc<Mutex<Vec<u8>>>,
}

impl TerminalDriver {
    fn new(
        exit_signal: Arc<AtomicBool>,
        to_kernel: TerminalInputFeeder,
        from_kernel: Arc<Mutex<Vec<u8>>>,
    ) -> Self {
        Self {
            exit_signal,
            to_kernel,
            from_kernel,
            line: CurrentLine::new(),
        }
    }

    pub fn run(mut self) {
        let mut stdout = io::stdout().into_raw_mode().unwrap();
        let mut stdin = termion::async_stdin().keys();

        loop {
            thread::sleep(time::Duration::from_millis(10));

            if self.exit_signal.load(Ordering::Relaxed) {
                break;
            }

            let should_exit = self.handle_input(&mut stdin, &mut stdout);
            if should_exit {
                break;
            }

            self.handle_output(&mut stdout);
        }

        eprintln!("Terminal driver exiting.");
    }

    fn handle_input(
        &mut self,
        stdin: &mut impl Iterator<Item = Result<Key, std::io::Error>>,
        stdout: &mut RawTerminal<std::io::Stdout>,
    ) -> bool {
        let input = stdin.next();
        if let Some(key_result) = input {
            let key = key_result.unwrap();
            match key {
                Key::Ctrl('c') => {
                    self.to_kernel.interrupt();
                    write!(stdout, "^C").unwrap();
                }

                Key::Ctrl('q') => {
                    write!(stdout, "QUITTING\r\n").unwrap();
                    stdout.lock().flush().unwrap();
                    return true;
                }

                Key::Ctrl('a') => {
                    self.line.start();
                    let line_number = termion::terminal_size().unwrap().1;
                    // note: cursor positions are 1-indexed
                    write!(
                        stdout,
                        "{}",
                        cursor::Goto(self.line.pos() as u16 + 1, line_number),
                    )
                    .unwrap();
                }

                Key::Ctrl('e') => {
                    self.line.end();
                    let line_number = termion::terminal_size().unwrap().1;
                    // note: cursor positions are 1-indexed
                    write!(
                        stdout,
                        "{}",
                        cursor::Goto(self.line.get().len() as u16 + 1, line_number),
                    )
                    .unwrap();
                }
                Key::Left => {
                    if self.line.left() {
                        write!(stdout, "{}", cursor::Left(1)).unwrap();
                    }
                }
                Key::Right => {
                    if self.line.right() {
                        write!(stdout, "{}", cursor::Right(1)).unwrap();
                    }
                }
                Key::Backspace => {
                    if self.line.backspace() {
                        redraw_line(stdout, self.line.get(), self.line.pos() as u16);
                    }
                }
                Key::Char('\t') => {
                    // ignore tabs, as they seem to mess with the rendering
                }

                Key::Char('\n') => {
                    let finished_line = self.line.new_line();
                    // Need to insert \r before line break as stdout is raw
                    write!(stdout, "\r\n").unwrap();
                    self.to_kernel.bytes(finished_line.as_bytes());
                }

                Key::Char(ch) => {
                    self.line.char(ch);
                    redraw_line(stdout, self.line.get(), self.line.pos() as u16);
                }

                _ => {
                    eprintln!("UNHANDLED TERMION INPUT: Key pressed: {:?}", key)
                }
            }
        }
        false
    }

    fn handle_output(&mut self, stdout: &mut RawTerminal<std::io::Stdout>) {
        let mut output = self.from_kernel.lock().unwrap();
        let str_output = String::from_utf8_lossy(&output[..]);
        if !str_output.is_empty() {
            eprintln!(
                "DEBUG terminal driver, output from Kernel: {:?}",
                str_output
            );
        }
        let ends_with_newline = str_output.ends_with('\n');
        let mut lines = str_output.lines();
        if let Some(line) = lines.next() {
            write!(stdout, "{}", line).unwrap();
            self.line.set(line.to_owned());
        }
        for line in lines {
            // Need to insert \r\n manually before any further lines, as stdout is raw
            write!(stdout, "\r\n{}", line).unwrap();
            self.line.set(line.to_owned());
        }
        if ends_with_newline {
            write!(stdout, "\r\n").unwrap();
            self.line.clear();
        }
        stdout.lock().flush().unwrap();
        output.clear();
    }
}

fn redraw_line(stdout: &mut RawTerminal<std::io::Stdout>, line: &str, cursor_pos: u16) {
    let line_number = termion::terminal_size().unwrap().1;
    // note: cursor positions are 1-indexed
    write!(
        stdout,
        "{}{}{}{}",
        cursor::Goto(1, line_number),
        clear::AfterCursor,
        line,
        cursor::Goto(cursor_pos + 1, line_number)
    )
    .unwrap();
}

struct CurrentLine {
    s: String,
    pos: usize,
    // If the line starts with a shell prompt, we're not allowed to edit that
    min_allowed_pos: usize,
}

impl CurrentLine {
    fn new() -> Self {
        Self {
            s: Default::default(),
            pos: 0,
            min_allowed_pos: 0,
        }
    }

    fn get(&self) -> &str {
        &self.s[..]
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn backspace(&mut self) -> bool {
        if self.pos > self.min_allowed_pos {
            self.s.remove(self.pos - 1);
            self.pos -= 1;
            true
        } else {
            false
        }
    }

    fn start(&mut self) {
        self.pos = self.min_allowed_pos;
    }

    fn end(&mut self) {
        self.pos = self.s.len()
    }

    fn left(&mut self) -> bool {
        if self.pos > self.min_allowed_pos {
            self.pos -= 1;
            true
        } else {
            false
        }
    }

    fn right(&mut self) -> bool {
        if self.pos < self.s.len() {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn char(&mut self, ch: char) {
        self.s.insert(self.pos, ch);
        self.pos += 1;
    }

    fn new_line(&mut self) -> String {
        self.s.push('\n');
        let line = std::mem::take(&mut self.s);
        let input = &line[self.min_allowed_pos..];
        self.clear();
        input.to_string()
    }

    fn clear(&mut self) {
        self.s.clear();
        self.min_allowed_pos = 0;
        self.pos = self.min_allowed_pos;
    }

    fn set(&mut self, s: String) {
        self.s = s;
        self.min_allowed_pos = self.s.len();
        self.pos = self.min_allowed_pos;
    }
}
