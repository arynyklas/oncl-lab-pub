//! The `.src.diff` of a copy in the project's Releases (`docs/design/publishers.md`, «Копии
//! пакетов в наших Releases»): the unified diff of the files of the previous version's source
//! archive and the new one's, under `a/src/` and `b/src/`, three lines of context, in the
//! form `git diff` prints. A binary file (a NUL byte, or not UTF-8) is named, not shown; a
//! text file whose diff would take more than [`MAX_EDITS`] edits is shown replaced whole.

use std::fmt::Write as _;

use oncl_pack::source::Tree;

/// Lines of context around a change.
const CONTEXT: usize = 3;

/// The most edits the diff of one file is computed for (the trace takes O(D²) memory); past
/// it the whole file is shown replaced.
const MAX_EDITS: usize = 2_000;

fn is_text(data: &[u8]) -> bool {
    !data.contains(&0) && std::str::from_utf8(data).is_ok()
}

/// `text` as lines, each with its line end.
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Same,
    Del,
    Add,
}

/// The edit script of `a` into `b` (Myers' O(ND) algorithm), `None` past [`MAX_EDITS`].
fn script(a: &[&str], b: &[&str]) -> Option<Vec<Op>> {
    let n = a.len() as isize;
    let m = b.len() as isize;
    let max = (n + m) as usize;
    let offset = max as isize + 1;
    let mut v = vec![0isize; 2 * max + 3];
    // trace[d]: `v` before step d, for the diagonals -(d+1)..=d+1 that step reads.
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = None;
    for d in 0..=max.min(MAX_EDITS) as isize {
        let lo = (offset - d - 1) as usize;
        trace.push(v[lo..=lo + 2 * d as usize + 2].to_vec());
        let mut k = -d;
        while k <= d {
            let at = (k + offset) as usize;
            let mut x = if k == -d || (k != d && v[at - 1] < v[at + 1]) {
                v[at + 1]
            } else {
                v[at - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[at] = x;
            if x >= n && y >= m {
                found = Some(d);
                break;
            }
            k += 2;
        }
        if found.is_some() {
            break;
        }
    }
    let d_end = found?;
    // Back through the trace, from the end.
    let mut ops = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..=d_end).rev() {
        let snapshot = &trace[d as usize];
        let v = |k: isize| snapshot[(k + d + 1) as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && v(k - 1) < v(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = if d == 0 { 0 } else { v(prev_k) };
        let prev_y = (prev_x - prev_k).max(0);
        while x > prev_x && y > prev_y {
            ops.push(Op::Same);
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                ops.push(Op::Add);
                y -= 1;
            } else {
                ops.push(Op::Del);
                x -= 1;
            }
        }
    }
    ops.reverse();
    Some(ops)
}

/// The hunks of a file's diff, `@@ -a,b +c,d @@` and the lines.
fn hunks(a: &[&str], b: &[&str], out: &mut String) {
    let ops = script(a, b).unwrap_or_else(|| {
        let mut ops = vec![Op::Del; a.len()];
        ops.extend(std::iter::repeat_n(Op::Add, b.len()));
        ops
    });
    // Positions (in `a`, in `b`) before each op.
    let mut at = Vec::with_capacity(ops.len() + 1);
    let (mut i, mut j) = (0usize, 0usize);
    for op in &ops {
        at.push((i, j));
        match op {
            Op::Same => {
                i += 1;
                j += 1;
            }
            Op::Del => i += 1,
            Op::Add => j += 1,
        }
    }
    at.push((i, j));
    let changed: Vec<usize> = (0..ops.len()).filter(|&k| ops[k] != Op::Same).collect();
    let mut k = 0;
    while k < changed.len() {
        let start = changed[k].saturating_sub(CONTEXT);
        let mut end = changed[k] + 1;
        while k + 1 < changed.len() && changed[k + 1] <= end + 2 * CONTEXT {
            k += 1;
            end = changed[k] + 1;
        }
        let end = (end + CONTEXT).min(ops.len());
        let (a0, b0) = at[start];
        let (a1, b1) = at[end];
        let range = |from: usize, len: usize| {
            if len == 0 {
                format!("{from},0")
            } else if len == 1 {
                format!("{}", from + 1)
            } else {
                format!("{},{len}", from + 1)
            }
        };
        let _ = writeln!(out, "@@ -{} +{} @@", range(a0, a1 - a0), range(b0, b1 - b0));
        for (n, op) in ops[start..end].iter().enumerate() {
            let (ia, ib) = at[start + n];
            let (sign, line) = match op {
                Op::Same => (' ', a[ia]),
                Op::Del => ('-', a[ia]),
                Op::Add => ('+', b[ib]),
            };
            out.push(sign);
            out.push_str(line);
            if !line.ends_with('\n') {
                out.push_str("\n\\ No newline at end of file\n");
            }
        }
        k += 1;
    }
}

/// The diff of one file, `None` for the same bytes.
fn file_diff(path: &str, old: Option<&[u8]>, new: Option<&[u8]>, out: &mut String) {
    if old == new {
        return;
    }
    let a_name = format!("a/src/{path}");
    let b_name = format!("b/src/{path}");
    let _ = writeln!(out, "diff --git {a_name} {b_name}");
    match (old, new) {
        (None, Some(_)) => {
            let _ = writeln!(out, "new file");
        }
        (Some(_), None) => {
            let _ = writeln!(out, "deleted file");
        }
        _ => {}
    }
    let text = old.is_none_or(is_text) && new.is_none_or(is_text);
    let from = if old.is_some() {
        a_name.as_str()
    } else {
        "/dev/null"
    };
    let to = if new.is_some() {
        b_name.as_str()
    } else {
        "/dev/null"
    };
    if !text {
        let _ = writeln!(out, "Binary files {from} and {to} differ");
        return;
    }
    let _ = writeln!(out, "--- {from}\n+++ {to}");
    let old_text = old.map(|d| String::from_utf8_lossy(d)).unwrap_or_default();
    let new_text = new.map(|d| String::from_utf8_lossy(d)).unwrap_or_default();
    hunks(&lines(&old_text), &lines(&new_text), out);
}

/// The diff of `old` (the previous version's sources) and `new`; for the first version, with
/// `old` `None`, every file of `new` as new.
pub fn trees(old: Option<&Tree>, new: &Tree) -> String {
    let mut out = String::new();
    let empty = Tree::new();
    let old = old.unwrap_or(&empty);
    let mut paths: Vec<&str> = old.files().map(|(p, _)| p).collect();
    paths.extend(new.files().map(|(p, _)| p));
    paths.sort_unstable();
    paths.dedup();
    for path in paths {
        let before = old.get(path).map(|f| f.data.as_slice());
        let after = new.get(path).map(|f| f.data.as_slice());
        file_diff(path, before, after, &mut out);
        if let (Some(a), Some(b)) = (old.get(path), new.get(path))
            && a.executable != b.executable
            && a.data == b.data
        {
            let _ = writeln!(
                out,
                "diff --git a/src/{path} b/src/{path}\nold mode {}\nnew mode {}",
                mode(a.executable),
                mode(b.executable)
            );
        }
    }
    out
}

fn mode(executable: bool) -> &'static str {
    if executable { "100755" } else { "100644" }
}

#[cfg(test)]
mod tests {
    use oncl_pack::source::File;

    use super::*;

    fn tree(files: &[(&str, &str)]) -> Tree {
        let mut tree = Tree::new();
        for (path, text) in files {
            tree.insert(
                path,
                File {
                    executable: false,
                    data: text.as_bytes().to_vec(),
                },
            )
            .unwrap();
        }
        tree
    }

    #[test]
    fn a_changed_line_is_a_hunk_with_its_context() {
        let old = tree(&[("a.rs", "1\n2\n3\n4\n5\n6\n7\n8\n9\n"), ("gone.rs", "x\n")]);
        let new = tree(&[("a.rs", "1\n2\n3\n4\nfive\n6\n7\n8\n9\n"), ("new.rs", "y")]);
        let diff = trees(Some(&old), &new);
        assert_eq!(
            diff,
            "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n\
             @@ -2,7 +2,7 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n\
             diff --git a/src/gone.rs b/src/gone.rs\ndeleted file\n--- a/src/gone.rs\n+++ /dev/null\n\
             @@ -1 +0,0 @@\n-x\n\
             diff --git a/src/new.rs b/src/new.rs\nnew file\n--- /dev/null\n+++ b/src/new.rs\n\
             @@ -0,0 +1 @@\n+y\n\\ No newline at end of file\n"
        );
    }

    #[test]
    fn the_same_sources_have_an_empty_diff_and_binaries_are_named() {
        let a = tree(&[("a.rs", "same\n")]);
        assert_eq!(trees(Some(&a), &a), "");
        let mut b = tree(&[("a.rs", "same\n")]);
        b.insert(
            "font.ttf",
            File {
                executable: false,
                data: vec![0, 1, 2],
            },
        )
        .unwrap();
        let diff = trees(Some(&a), &b);
        assert!(
            diff.contains("Binary files /dev/null and b/src/font.ttf differ"),
            "{diff}"
        );
    }

    #[test]
    fn edits_far_apart_are_two_hunks() {
        let old: Vec<String> = (1..=30).map(|n| format!("{n}\n")).collect();
        let mut new = old.clone();
        new[2] = "three\n".to_owned();
        new[25] = "twenty-six\n".to_owned();
        let (old, new) = (old.concat(), new.concat());
        let diff = trees(Some(&tree(&[("f", &old)])), &tree(&[("f", &new)]));
        assert_eq!(diff.matches("@@ -").count(), 2, "{diff}");
        assert!(
            diff.contains("-3\n+three\n") && diff.contains("-26\n+twenty-six\n"),
            "{diff}"
        );
    }
}
