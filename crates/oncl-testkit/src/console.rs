//! Tests that need a real Windows console (Ctrl-Break delivery, a pseudoconsole) cannot run
//! where cargo has none: an IDE runner, a service, an agent shell. They skip there with a
//! `skipped:` line, as a test whose program is missing does ([`crate::tool`]), and with
//! [`REQUIRE_ENV`] set (CI) the missing console fails the test instead.

use crate::tool::{REQUIRE_ENV, current_test, oracles_required};
use std::io::Write as _;

/// Whether the test may go on: `available` says whether `what` (a console feature) works
/// here. When it does not, the test skips: `false`, after a line on stderr that bypasses the
/// harness' output capture.
///
/// # Panics
///
/// If `what` is missing and [`oracles_required`].
#[must_use]
pub fn proceed(what: &str, available: bool) -> bool {
    if available {
        return true;
    }
    let test = current_test();
    assert!(
        !oracles_required(),
        "{test} needs {what}, which is missing. The test fails rather than skips because \
         {REQUIRE_ENV} is set (unset it, or set it to 0, to skip instead)."
    );
    let _ = writeln!(
        std::io::stderr().lock(),
        "skipped: {test} needs {what}; see docs/dev/development.md «Что нужно для тестов»"
    );
    false
}

/// Whether this process is attached to a console, which a Ctrl-Break sent to a child of its
/// own process group needs: without one `GenerateConsoleCtrlEvent` fails.
#[cfg(windows)]
#[must_use]
pub fn attached() -> bool {
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    let mut pid = 0u32;
    // SAFETY: a one-element buffer of the stated size; the call only counts the processes
    // that share the console (0 when there is none).
    unsafe { GetConsoleProcessList(&raw mut pid, 1) != 0 }
}

/// Whether a test may deliver Ctrl-Break to its child; see [`proceed`].
///
/// # Panics
///
/// If there is no console and [`oracles_required`].
#[cfg(windows)]
#[must_use]
pub fn ctrl_break_possible() -> bool {
    proceed("a console to deliver CTRL_BREAK through", attached())
}

#[cfg(test)]
mod tests {
    use super::proceed;

    #[test]
    fn an_available_feature_proceeds() {
        assert!(proceed("anything", true));
    }
}
