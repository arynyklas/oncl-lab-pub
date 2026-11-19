//! External programs the tests run (OpenSSL, Python, Java's `keytool`, Git, NSS's
//! `certutil`): where to find them and what a test does when one is missing.
//!
//! A test that needs a program which is not installed is skipped: it prints one line to stderr
//! (`skipped: <test> needs <program> (not found: tried ...); see ...`) and returns early, so it
//! passes. With [`REQUIRE_ENV`] set to anything but empty or `0` (CI sets `1`) the same absence
//! fails the test with
//! the full [`message`]: which executable names were tried, which environment variable
//! overrides them, which package provides the program and where the list of everything the
//! tests need is kept, so a contributor does not have to read test code to learn what to put
//! on `PATH`.
//!
//! The lookups ([`openssl`], [`Tool::lookup`], ...) never panic; the `*_or_skip` forms make the
//! decision, and a test early-returns on their `None`:
//!
//! ```no_run
//! let Some(openssl) = oncl_testkit::tool::openssl_or_skip() else {
//!     return;
//! };
//! # let _ = openssl;
//! ```
//!
//! Lookup order, where a program has an override: the override variable, then the executable
//! names on `PATH` (on Windows the OpenSSL of Git for Windows last).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};

/// Where the dependencies of the tests are listed.
const DOCS: &str = "docs/dev/development.md, section «Что нужно для тестов»";

/// Environment variable that turns a missing program from a skipped test into a failed one.
/// Unset, empty or `0` skips; any other value fails (fail closed: a typo such as `true` or
/// `yes` still requires the programs). CI sets it to `1`.
pub const REQUIRE_ENV: &str = "ONCL_REQUIRE_ORACLES";
/// Environment variable naming the OpenSSL executable.
pub const OPENSSL_ENV: &str = "ONCL_OPENSSL";
/// Environment variable naming the Python interpreter of the independent checks.
pub const PYTHON_ENV: &str = "ONCL_PYHANKO_PYTHON";

/// What provides a Python with the modules of the independent checks.
const PYTHON_PROVIDES: &str = "Python 3 with the modules the check imports, installed in a \
    separate virtual environment, not the system Python: `python -m venv .venv-oracle`, then \
    that environment's pip installs `-r xtask/assets/oracle/requirements.txt` (pyHanko, \
    pyhanko-certvalidator, lxml, cryptography); its python is `.venv-oracle\\Scripts\\python.exe` \
    on Windows and `.venv-oracle/bin/python` on Linux and macOS";

/// Whether a missing program fails the test instead of skipping it: [`REQUIRE_ENV`] is set to
/// a value other than empty or `0`.
#[must_use]
pub fn oracles_required() -> bool {
    required_by(std::env::var_os(REQUIRE_ENV).as_deref())
}

/// [`oracles_required`] for a given value of [`REQUIRE_ENV`].
fn required_by(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != OsStr::new("0"))
}

/// The executable names, quoted and comma-separated.
fn quoted(tried: &[String]) -> String {
    tried
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Message for a program the tests need and cannot find: the executable names tried, the
/// override variable (with its current value), what provides the program and the document
/// listing the test dependencies.
#[must_use]
pub fn message(tried: &[String], env: Option<&str>, provides: &str) -> String {
    let mut text = String::from("a program the tests need is not installed.");
    if !tried.is_empty() {
        let _ = write!(text, " Executables tried: {}.", quoted(tried));
    }
    if let Some(var) = env {
        match std::env::var_os(var) {
            Some(value) => {
                let _ = write!(
                    text,
                    " Override: {var} is set to `{}` (set it to a working executable).",
                    value.to_string_lossy()
                );
            }
            None => {
                let _ = write!(
                    text,
                    " Override: set {var} to the path of the executable (it is not set)."
                );
            }
        }
    }
    let _ = write!(text, " Provided by: {provides}. See {DOCS}.");
    text
}

/// A program the tests need and did not find; its [`Display`](std::fmt::Display) is the full
/// [`message`].
#[derive(Clone, Debug)]
pub struct Missing {
    /// The program, as the skip line names it (`openssl`, `a Python with lxml`).
    program: String,
    /// Executables tried, in order.
    tried: Vec<String>,
    /// Environment variable that overrides the executable.
    env: Option<&'static str>,
    /// What provides it.
    provides: String,
}

impl Missing {
    /// A program a lookup outside this module did not find: `program` as the skip line names it,
    /// the executables `tried`, the override variable `env` and what `provides` it.
    #[must_use]
    pub fn new(
        program: impl Into<String>,
        tried: Vec<String>,
        env: Option<&'static str>,
        provides: impl Into<String>,
    ) -> Self {
        Self {
            program: program.into(),
            tried,
            env,
            provides: provides.into(),
        }
    }

    /// The full message: see [`message`].
    #[must_use]
    pub fn message(&self) -> String {
        message(&self.tried, self.env, &self.provides)
    }

    /// The one line a skipped test prints: the test (the name of the running test thread),
    /// the program, what was tried and where the test dependencies are listed.
    #[must_use]
    pub fn skip_line(&self) -> String {
        let test = current_test();
        let mut tried = Vec::new();
        if !self.tried.is_empty() {
            tried.push(format!("tried {}", quoted(&self.tried)));
        }
        if let Some(var) = self.env.filter(|var| std::env::var_os(var).is_none()) {
            tried.push(format!("{var} is not set"));
        }
        format!(
            "skipped: {test} needs {} (not found: {}); see docs/dev/development.md «Что нужно \
             для тестов»",
            self.program,
            tried.join("; ")
        )
    }
}

/// The running test, as a skip line names it: the name of the current thread, which the test
/// harness names after the test.
pub(crate) fn current_test() -> String {
    std::thread::current()
        .name()
        .filter(|name| *name != "main")
        .unwrap_or("this check")
        .to_owned()
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for Missing {}

/// What happens to a test whose program lookup gave `found`: the program, or the skip line
/// when the program is missing and `required` is false.
///
/// # Panics
///
/// If the program is missing and `required` is true, with the full [`message`].
fn decide<T>(found: Result<T, Missing>, required: bool) -> Result<T, String> {
    match found {
        Ok(value) => Ok(value),
        Err(missing) if required => panic!(
            "{} is missing: {missing} The test fails rather than skips because {REQUIRE_ENV} \
             is set (unset it, or set it to 0, to skip instead).",
            missing.program
        ),
        Err(missing) => Err(missing.skip_line()),
    }
}

/// The program `found`, or `None` after the skip line on stderr when it is missing; the
/// caller returns early from the test on `None`. The line bypasses the test harness' output
/// capture, so `cargo test` shows it for a passing test too.
///
/// # Panics
///
/// If the program is missing and [`oracles_required`], with the full [`message`].
pub fn or_skip<T>(found: Result<T, Missing>) -> Option<T> {
    match decide(found, oracles_required()) {
        Ok(value) => Some(value),
        Err(line) => {
            let _ = writeln!(std::io::stderr().lock(), "{line}");
            None
        }
    }
}

/// A program that is run by name.
#[derive(Clone, Copy, Debug)]
pub struct Tool {
    /// Executable names tried on `PATH`, in order.
    pub names: &'static [&'static str],
    /// Environment variable that names the executable, tried first.
    pub env: Option<&'static str>,
    /// What provides it.
    pub provides: &'static str,
}

/// OpenSSL 3 (with `cms`, `ts` and `dgst`).
pub const OPENSSL: Tool = Tool {
    names: &["openssl"],
    env: Some(OPENSSL_ENV),
    provides: "OpenSSL 3 (Linux: the `openssl` package; macOS: `brew install openssl@3`; \
        Windows: Git for Windows, whose `usr/bin/openssl.exe` is found by itself, or any \
        OpenSSL 3 build)",
};

/// Java's `keytool`.
pub const KEYTOOL: Tool = Tool {
    names: &["keytool"],
    env: None,
    provides: "a JDK: keytool is in its bin/ directory, which must be on PATH",
};

/// Git.
pub const GIT: Tool = Tool {
    names: &["git"],
    env: None,
    provides: "Git (https://git-scm.com/)",
};

/// NSS's `certutil` (the Linux trust-store tests).
pub const CERTUTIL: Tool = Tool {
    names: &["certutil"],
    env: None,
    provides: "the NSS tools (Debian/Ubuntu: `libnss3-tools`; Fedora: `nss-tools`)",
};

/// A Python 3 whose standard library is all a script needs; any interpreter will do.
pub const PYTHON_STDLIB: Tool = Tool {
    names: &["python", "python3", "py"],
    env: Some(PYTHON_ENV),
    provides: "Python 3 (any interpreter; the standard library is enough for this check)",
};

/// A Python 3 that has to import extra modules; see [`python_with`].
const PYTHON: Tool = Tool {
    names: &["python", "python3", "py"],
    env: Some(PYTHON_ENV),
    provides: PYTHON_PROVIDES,
};

impl Tool {
    /// The candidates in lookup order: the override variable's value, the names, and for
    /// OpenSSL on Windows the copy inside Git for Windows.
    #[must_use]
    pub fn candidates(&self) -> Vec<String> {
        self.candidates_with(|var| std::env::var(var).ok())
    }

    /// [`Tool::candidates`] with `var` giving the override variable's value.
    fn candidates_with(&self, var: impl Fn(&str) -> Option<String>) -> Vec<String> {
        let mut found = Vec::new();
        if let Some(value) = self.env.and_then(var) {
            found.push(value);
        }
        found.extend(self.names.iter().map(|name| (*name).to_owned()));
        if cfg!(windows) && self.names == ["openssl"] {
            for var in ["ProgramFiles", "ProgramW6432"] {
                if let Some(base) = std::env::var_os(var) {
                    found.push(
                        Path::new(&base)
                            .join("Git/usr/bin/openssl.exe")
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        let mut unique: Vec<String> = Vec::with_capacity(found.len());
        for candidate in found {
            if !unique.contains(&candidate) {
                unique.push(candidate);
            }
        }
        unique
    }

    /// The tool as missing, having tried `tried`.
    fn missing(&self, tried: Vec<String>) -> Missing {
        Missing {
            program: self.names[0].to_owned(),
            tried,
            env: self.env,
            provides: self.provides.to_owned(),
        }
    }

    /// The first candidate for which `<candidate> <probe args>` exits successfully, or what
    /// was tried.
    ///
    /// # Errors
    ///
    /// [`Missing`] when no candidate runs.
    pub fn lookup(&self, probe: &[&str]) -> Result<String, Missing> {
        // One probe per program and probe per process: every test of a binary asks again.
        static FOUND: LazyLock<Mutex<HashMap<String, Result<String, Missing>>>> =
            LazyLock::new(Mutex::default);
        let key = format!("{:?} {:?} {probe:?}", self.names, self.env);
        let cache = &*FOUND;
        if let Some(found) = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
        {
            return found.clone();
        }
        let found = self.lookup_with(probe, |var| std::env::var(var).ok());
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, found.clone());
        found
    }

    /// [`Tool::lookup`] with `var` giving the override variable's value.
    fn lookup_with(
        &self,
        probe: &[&str],
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<String, Missing> {
        let candidates = self.candidates_with(var);
        match candidates.iter().find(|candidate| {
            Command::new(candidate)
                .args(probe)
                .stdin(Stdio::null())
                .output()
                .is_ok_and(|output| output.status.success())
        }) {
            Some(found) => Ok(found.clone()),
            None => Err(self.missing(candidates)),
        }
    }

    /// [`Tool::lookup`] under [`or_skip`]: the executable, or `None` after the skip line.
    ///
    /// # Panics
    ///
    /// If no candidate runs and [`oracles_required`].
    #[must_use]
    pub fn or_skip(&self, probe: &[&str]) -> Option<String> {
        or_skip(self.lookup(probe))
    }

    /// The result of running the tool by its first name (`Command::new(name)….output()`)
    /// under [`or_skip`]: `None` after the skip line when the program cannot be started
    /// because it is not there. Any other I/O error fails the test as it is.
    ///
    /// # Panics
    ///
    /// If the program is not installed and [`oracles_required`], or could not be run.
    pub fn spawned_or_skip<T>(&self, result: std::io::Result<T>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                or_skip(Err(self.missing(self.candidates())))
            }
            Err(error) => panic!("cannot run `{}`: {error}", self.names[0]),
        }
    }
}

/// The OpenSSL executable: [`OPENSSL_ENV`], `openssl` on `PATH`, then (Windows) the copy in
/// Git for Windows; the first that runs `openssl version`.
///
/// # Errors
///
/// [`Missing`] when none of them runs.
pub fn openssl() -> Result<String, Missing> {
    OPENSSL.lookup(&["version"])
}

/// [`openssl`] under [`or_skip`].
///
/// # Panics
///
/// If OpenSSL is missing and [`oracles_required`].
#[must_use]
pub fn openssl_or_skip() -> Option<String> {
    or_skip(openssl())
}

/// A Python that imports `modules` (for example `"lxml, cryptography"`): [`PYTHON_ENV`]
/// first (the virtual environment of CI and of `xtask`), then `python`, `python3` and `py`
/// on `PATH`, which on a CI runner have no lxml.
///
/// # Errors
///
/// [`Missing`] when no Python imports `modules`.
pub fn python_with(modules: &str) -> Result<String, Missing> {
    PYTHON
        .lookup(&["-c", &format!("import {modules}")])
        .map_err(|missing| Missing {
            program: format!("a Python with {modules}"),
            provides: format!("{PYTHON_PROVIDES}. This check imports: {modules}"),
            ..missing
        })
}

/// [`python_with`] under [`or_skip`].
///
/// # Panics
///
/// If no Python imports `modules` and [`oracles_required`].
#[must_use]
pub fn python_with_or_skip(modules: &str) -> Option<String> {
    or_skip(python_with(modules))
}

/// Any working Python 3, for scripts that use only the standard library, under [`or_skip`].
///
/// # Panics
///
/// If no Python runs and [`oracles_required`].
#[must_use]
pub fn python_or_skip() -> Option<String> {
    PYTHON_STDLIB.or_skip(&["--version"])
}

/// The interpreter [`PYTHON_ENV`] names, for the checks that need pyHanko and must not run
/// with whichever `python` is first on `PATH` (it has no pyHanko or lxml on a CI runner).
///
/// # Errors
///
/// [`Missing`] when the variable is unset or does not name an existing file.
pub fn pyhanko_python() -> Result<PathBuf, Missing> {
    let value = std::env::var_os(PYTHON_ENV);
    match value.as_ref().map(PathBuf::from) {
        Some(path) if path.is_file() => Ok(path),
        _ => Err(Missing {
            program: format!("the Python with pyHanko named by {PYTHON_ENV}"),
            tried: value
                .map(|value| vec![value.to_string_lossy().into_owned()])
                .unwrap_or_default(),
            env: Some(PYTHON_ENV),
            provides: format!(
                "{PYTHON_PROVIDES}. There is no PATH fallback: {PYTHON_ENV} must name that \
                 environment's python executable"
            ),
        }),
    }
}

/// [`pyhanko_python`] under [`or_skip`].
///
/// # Panics
///
/// If [`PYTHON_ENV`] does not name a file and [`oracles_required`].
#[must_use]
pub fn pyhanko_python_or_skip() -> Option<PathBuf> {
    or_skip(pyhanko_python())
}

/// The `keytool` executable of a JDK under [`or_skip`].
///
/// # Panics
///
/// If `keytool` does not run and [`oracles_required`].
#[must_use]
pub fn keytool_or_skip() -> Option<String> {
    KEYTOOL.or_skip(&["-help"])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A program no machine has, with an override variable no environment sets.
    const ABSENT: Tool = Tool {
        names: &["oncl-no-such-program"],
        env: Some("ONCL_TOOL_THAT_IS_NEVER_SET"),
        provides: "nothing",
    };

    /// The override variable unset.
    fn unset(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn message_names_executables_variable_package_and_document() {
        let text = message(
            &["openssl".to_owned(), "/opt/git/usr/bin/openssl".to_owned()],
            Some("ONCL_TOOL_THAT_IS_NEVER_SET"),
            "OpenSSL 3",
        );
        assert!(
            text.contains("`openssl`, `/opt/git/usr/bin/openssl`"),
            "{text}"
        );
        assert!(text.contains("ONCL_TOOL_THAT_IS_NEVER_SET"), "{text}");
        assert!(text.contains("OpenSSL 3"), "{text}");
        assert!(text.contains("Что нужно для тестов"), "{text}");
    }

    #[test]
    fn only_unset_empty_or_0_leaves_the_programs_optional() {
        assert!(!required_by(None));
        assert!(!required_by(Some(OsStr::new(""))));
        assert!(!required_by(Some(OsStr::new("0"))));
        assert!(required_by(Some(OsStr::new("1"))));
        assert!(required_by(Some(OsStr::new("true"))));
        assert!(required_by(Some(OsStr::new("yes"))));
    }

    #[test]
    fn the_override_variable_finds_a_program_that_is_not_on_path() {
        let cargo = env!("CARGO").to_owned();
        let found = ABSENT.lookup_with(&["--version"], |_| Some(cargo.clone()));
        assert_eq!(found.ok(), Some(cargo));
    }

    #[test]
    fn a_program_neither_on_path_nor_overridden_is_missing_with_what_was_tried() {
        let Err(missing) = ABSENT.lookup_with(&["--version"], unset) else {
            panic!("oncl-no-such-program was found");
        };
        assert_eq!(missing.tried, ["oncl-no-such-program"]);
        let overridden = ABSENT
            .lookup_with(&["--version"], |_| Some("/nonexistent/oncl".to_owned()))
            .err()
            .map(|missing| missing.tried);
        assert_eq!(
            overridden,
            Some(vec![
                "/nonexistent/oncl".to_owned(),
                "oncl-no-such-program".to_owned()
            ])
        );
    }

    #[test]
    fn a_found_program_runs_whether_or_not_programs_are_required() {
        let cargo = env!("CARGO").to_owned();
        for required in [false, true] {
            let found = ABSENT.lookup_with(&["--version"], |_| Some(cargo.clone()));
            assert_eq!(decide(found, required), Ok(cargo.clone()));
        }
    }

    #[test]
    fn a_missing_program_skips_the_test_with_one_line_when_not_required() {
        let line = decide(ABSENT.lookup_with(&["--version"], unset), false)
            .expect_err("the missing program skips");
        assert!(
            line.starts_with(
                "skipped: tool::tests::a_missing_program_skips_the_test_with_one_line_when_not_required \
                 needs oncl-no-such-program (not found: tried `oncl-no-such-program`; \
                 ONCL_TOOL_THAT_IS_NEVER_SET is not set); see docs/dev/development.md"
            ),
            "{line}"
        );
        assert!(line.ends_with("«Что нужно для тестов»"), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    #[test]
    #[should_panic(
        expected = "oncl-no-such-program is missing: a program the tests need is not \
                    installed. Executables tried: `oncl-no-such-program`. Override: set \
                    ONCL_TOOL_THAT_IS_NEVER_SET to the path of the executable (it is not set). \
                    Provided by: nothing. See docs/dev/development.md, section «Что нужно для \
                    тестов». The test fails rather than skips because ONCL_REQUIRE_ORACLES is set"
    )]
    fn a_missing_program_fails_the_test_with_the_full_message_when_required() {
        let _ = decide(ABSENT.lookup_with(&["--version"], unset), true);
    }

    #[test]
    fn spawning_a_missing_program_is_reported_as_missing() {
        let tool = Tool {
            names: &["oncl-no-such-program"],
            env: None,
            provides: "nothing",
        };
        let spawned = Command::new("oncl-no-such-program").output();
        let Err(error) = &spawned else {
            panic!("oncl-no-such-program started");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let line = decide::<()>(Err(tool.missing(tool.candidates())), false)
            .expect_err("the missing program skips");
        assert!(line.contains("needs oncl-no-such-program"), "{line}");
    }
}
