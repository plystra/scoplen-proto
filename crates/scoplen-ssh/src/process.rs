// SPDX-License-Identifier: Apache-2.0
//! A bounded desktop `ProxyCommand` byte transport.
//!
//! The command is started directly with separated arguments; no shell is involved.  Standard
//! input and output form the byte stream consumed by an SSH engine.  The child is always reaped
//! when the transport is dropped, and the public boundary never exposes command output or paths
//! in an error message.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    ffi::OsStr,
    fmt,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
};

use thiserror::Error;

use crate::tcp::{Transport, TransportError, TransportOperation};

/// Maximum length of a `ProxyCommand` executable path or name.
pub const MAX_PROXY_COMMAND_PROGRAM: usize = 4096;
/// Maximum number of arguments accepted by a `ProxyCommand`.
pub const MAX_PROXY_COMMAND_ARGUMENTS: usize = 64;
/// Maximum length of one `ProxyCommand` argument.
pub const MAX_PROXY_COMMAND_ARGUMENT: usize = 4096;

/// Errors raised before a `ProxyCommand` transport can be created.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProxyCommandError {
    /// The executable path or name was empty.
    #[error("ProxyCommand program is empty")]
    EmptyProgram,
    /// The executable path or name exceeded the bound.
    #[error("ProxyCommand program exceeds the {max}-byte limit")]
    ProgramTooLong { max: usize },
    /// An argument exceeded the bound.
    #[error("ProxyCommand argument exceeds the {max}-byte limit")]
    ArgumentTooLong { max: usize },
    /// The argument list exceeded the bound.
    #[error("ProxyCommand has more than {max} arguments")]
    TooManyArguments { max: usize },
    /// The operating system rejected process creation.
    #[error("ProxyCommand process could not be started: {kind:?}")]
    Spawn { kind: io::ErrorKind },
    /// A piped standard stream was unexpectedly unavailable after process creation.
    #[error("ProxyCommand process did not provide {stream}")]
    MissingPipe { stream: &'static str },
}

/// A byte transport backed by a directly spawned `ProxyCommand` process.
pub struct ProxyCommandTransport {
    stdin: Mutex<Option<ChildStdin>>,
    stdout: Mutex<Option<ChildStdout>>,
    child: Mutex<Child>,
}

impl fmt::Debug for ProxyCommandTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProxyCommandTransport").finish_non_exhaustive()
    }
}

impl ProxyCommandTransport {
    /// Spawn a process with piped standard input and output.
    ///
    /// Arguments are passed directly to [`Command`]. No shell, interpolation, environment
    /// expansion, or implicit command-line parsing is performed. Standard error is discarded so
    /// an unbounded child diagnostic cannot deadlock the byte transport.
    pub fn spawn<I, A>(program: impl AsRef<OsStr>, args: I) -> Result<Self, ProxyCommandError>
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        let program = program.as_ref();
        validate_program(program)?;

        let mut arguments = Vec::new();
        for argument in args {
            if arguments.len() >= MAX_PROXY_COMMAND_ARGUMENTS {
                return Err(ProxyCommandError::TooManyArguments {
                    max: MAX_PROXY_COMMAND_ARGUMENTS,
                });
            }
            let argument = argument.as_ref();
            validate_argument(argument)?;
            arguments.push(argument.to_os_string());
        }

        let mut command = Command::new(program);
        command.args(&arguments).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child =
            command.spawn().map_err(|error| ProxyCommandError::Spawn { kind: error.kind() })?;
        let Some(stdin) = child.stdin.take() else {
            reap_child(&mut child);
            return Err(ProxyCommandError::MissingPipe { stream: "stdin" });
        };
        let Some(stdout) = child.stdout.take() else {
            reap_child(&mut child);
            return Err(ProxyCommandError::MissingPipe { stream: "stdout" });
        };
        Ok(Self {
            stdin: Mutex::new(Some(stdin)),
            stdout: Mutex::new(Some(stdout)),
            child: Mutex::new(child),
        })
    }

    fn lock_error() -> io::Error {
        io::Error::new(io::ErrorKind::Other, "ProxyCommand transport state is unavailable")
    }

    fn take_stdin(&self) {
        if let Ok(mut stdin) = self.stdin.lock() {
            let _ = stdin.take();
        }
    }

    fn take_stdout(&self) {
        if let Ok(mut stdout) = self.stdout.lock() {
            let _ = stdout.take();
        }
    }

    fn kill_child(&self) -> io::Result<()> {
        let mut child = self.child.lock().map_err(|_| Self::lock_error())?;
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => return Ok(()),
            Err(error) => return Err(error),
        }
        child.wait().map(|_| ())
    }
}

impl Transport for ProxyCommandTransport {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        let mut stdout = self.stdout.lock().map_err(|_| TransportError::Io {
            operation: TransportOperation::Read,
            kind: io::ErrorKind::Other,
        })?;
        let stdout = stdout.as_mut().ok_or(TransportError::Io {
            operation: TransportOperation::Read,
            kind: io::ErrorKind::BrokenPipe,
        })?;
        stdout.read(buffer).map_err(|error| TransportError::Io {
            operation: TransportOperation::Read,
            kind: error.kind(),
        })
    }

    fn write(&mut self, buffer: &[u8]) -> Result<usize, TransportError> {
        let mut stdin = self.stdin.lock().map_err(|_| TransportError::Io {
            operation: TransportOperation::Write,
            kind: io::ErrorKind::Other,
        })?;
        let stdin = stdin.as_mut().ok_or(TransportError::Io {
            operation: TransportOperation::Write,
            kind: io::ErrorKind::BrokenPipe,
        })?;
        stdin.write(buffer).map_err(|error| TransportError::Io {
            operation: TransportOperation::Write,
            kind: error.kind(),
        })
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        let mut stdin = self.stdin.lock().map_err(|_| TransportError::Io {
            operation: TransportOperation::Flush,
            kind: io::ErrorKind::Other,
        })?;
        let stdin = stdin.as_mut().ok_or(TransportError::Io {
            operation: TransportOperation::Flush,
            kind: io::ErrorKind::BrokenPipe,
        })?;
        stdin.flush().map_err(|error| TransportError::Io {
            operation: TransportOperation::Flush,
            kind: error.kind(),
        })
    }

    fn shutdown(&self, how: Shutdown) -> Result<(), TransportError> {
        match how {
            Shutdown::Read => self.take_stdout(),
            Shutdown::Write => self.take_stdin(),
            Shutdown::Both => {
                self.take_stdin();
                self.take_stdout();
                self.kill_child().map_err(|error| TransportError::Io {
                    operation: TransportOperation::Shutdown,
                    kind: error.kind(),
                })?;
            }
        }
        Ok(())
    }

    fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Err(TransportError::Io {
            operation: TransportOperation::LocalAddress,
            kind: io::ErrorKind::NotConnected,
        })
    }

    fn peer_addr(&self) -> Result<SocketAddr, TransportError> {
        Err(TransportError::Io {
            operation: TransportOperation::PeerAddress,
            kind: io::ErrorKind::NotConnected,
        })
    }
}

impl Read for ProxyCommandTransport {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        Transport::read(self, buffer).map_err(Into::into)
    }
}

impl Write for ProxyCommandTransport {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Transport::write(self, buffer).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Transport::flush(self).map_err(Into::into)
    }
}

impl Drop for ProxyCommandTransport {
    fn drop(&mut self) {
        let _ = self.stdin.get_mut().ok().and_then(Option::take);
        let _ = self.stdout.get_mut().ok().and_then(Option::take);
        if let Ok(child) = self.child.get_mut() {
            reap_child(child);
        }
    }
}

fn validate_program(program: &OsStr) -> Result<(), ProxyCommandError> {
    if program.is_empty() {
        return Err(ProxyCommandError::EmptyProgram);
    }
    if program.to_string_lossy().len() > MAX_PROXY_COMMAND_PROGRAM {
        return Err(ProxyCommandError::ProgramTooLong { max: MAX_PROXY_COMMAND_PROGRAM });
    }
    Ok(())
}

fn validate_argument(argument: &OsStr) -> Result<(), ProxyCommandError> {
    if argument.to_string_lossy().len() > MAX_PROXY_COMMAND_ARGUMENT {
        return Err(ProxyCommandError::ArgumentTooLong { max: MAX_PROXY_COMMAND_ARGUMENT });
    }
    Ok(())
}

fn reap_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, ffi::OsString};

    fn echo_command() -> (OsString, Vec<OsString>) {
        #[cfg(windows)]
        {
            (
                env::var_os("ComSpec").unwrap_or_else(|| OsString::from("cmd.exe")),
                vec![OsString::from("/C"), OsString::from("more")],
            )
        }
        #[cfg(not(windows))]
        {
            (OsString::from("/bin/sh"), vec![OsString::from("-c"), OsString::from("cat")])
        }
    }

    #[test]
    fn process_round_trips_and_closes_stdin() {
        let (program, args) = echo_command();
        let mut transport = ProxyCommandTransport::spawn(program, args).expect("spawn echo");
        transport.write_all(b"proxy-command\n").expect("write input");
        Write::flush(&mut transport).expect("flush input");
        transport.shutdown(Shutdown::Write).expect("close stdin");
        let mut response = Vec::new();
        transport.read_to_end(&mut response).expect("read echo");
        assert!(response.windows(b"proxy-command".len()).any(|window| window == b"proxy-command"));
        assert!(matches!(
            transport.local_addr(),
            Err(TransportError::Io {
                operation: TransportOperation::LocalAddress,
                kind: io::ErrorKind::NotConnected
            })
        ));
    }

    #[test]
    fn process_inputs_are_bounded_and_spawn_errors_are_typed() {
        assert!(matches!(
            ProxyCommandTransport::spawn("", std::iter::empty::<&str>()),
            Err(ProxyCommandError::EmptyProgram)
        ));
        assert!(matches!(
            ProxyCommandTransport::spawn(
                "echo",
                std::iter::repeat("arg").take(MAX_PROXY_COMMAND_ARGUMENTS + 1)
            ),
            Err(ProxyCommandError::TooManyArguments { max: MAX_PROXY_COMMAND_ARGUMENTS })
        ));
        assert!(matches!(
            ProxyCommandTransport::spawn(
                OsString::from("echo"),
                [OsString::from("x".repeat(MAX_PROXY_COMMAND_ARGUMENT + 1))]
            ),
            Err(ProxyCommandError::ArgumentTooLong { max: MAX_PROXY_COMMAND_ARGUMENT })
        ));
        assert!(matches!(
            ProxyCommandTransport::spawn(
                OsString::from("scoplen-command-that-does-not-exist"),
                std::iter::empty::<OsString>()
            ),
            Err(ProxyCommandError::Spawn { .. })
        ));
    }
}
