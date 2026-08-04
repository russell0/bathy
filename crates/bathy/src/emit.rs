//! The two output channels, and the rule that keeps them separable.
//!
//! AC-5.10: under `--json`, **stdout carries line-delimited JSON and
//! nothing else**, and every diagnostic goes to stderr. That has to hold on
//! the failure paths too -- which is where it usually breaks, because a
//! failure is the moment a program is most tempted to print an explanation
//! wherever it happens to be standing.
//!
//! So there is exactly one type that writes to stdout and it only knows how
//! to write a `serde_json::Value` (as one line) or a human line, never both
//! for the same event, and the human sentence for a failure always goes to
//! stderr regardless of mode.

use std::io::Write;

use crate::exit::CliError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Human,
    Json,
}

pub struct Emitter {
    mode: Mode,
}

impl Emitter {
    pub fn new(json: bool) -> Self {
        Self {
            mode: if json { Mode::Json } else { Mode::Human },
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// One result. Under `--json` this is one line of JSON on stdout; in
    /// human mode it is `human` on stdout.
    ///
    /// Flushed immediately, not left to the process to drain at exit:
    /// `scan start` prints its handle and then keeps running for the whole
    /// scan (AC-5.12), so a buffered handle would be indistinguishable from
    /// a blocked one to anything reading the pipe.
    pub fn result(&self, value: serde_json::Value, human: impl std::fmt::Display) {
        let mut out = std::io::stdout().lock();
        match self.mode {
            Mode::Json => {
                let _ = writeln!(out, "{value}");
            }
            Mode::Human => {
                let _ = writeln!(out, "{human}");
            }
        }
        let _ = out.flush();
    }

    /// A diagnostic. **Always stderr, in both modes** -- this is the half
    /// of AC-5.10 that keeps stdout parseable.
    pub fn note(&self, message: impl std::fmt::Display) {
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "{message}");
        let _ = err.flush();
    }

    /// A failure. The machine-readable document goes to stdout under
    /// `--json` (stdout is the answer channel; a refusal is an answer), and
    /// the human sentence goes to stderr in **both** modes.
    pub fn failure(&self, error: &CliError) {
        if self.mode == Mode::Json {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{}", error.to_json());
            let _ = out.flush();
        }
        self.note(format!("bathy: {error}"));
    }
}
