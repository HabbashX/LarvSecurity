//! Minimal line-diff (LCS on lines, capped input) for the Diff Viewer.
//! No external diff crate — small, dependency-free, never panics.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Same(String),
    Del(String),
    Add(String),
}

/// Cap to keep the O(n·m) table small.
const MAX_LINES: usize = 2000;

pub fn diff_lines(a: &str, b: &str) -> Vec<DiffOp> {
    let al: Vec<&str> = a.lines().take(MAX_LINES).collect();
    let bl: Vec<&str> = b.lines().take(MAX_LINES).collect();
    let n = al.len();
    let m = bl.len();
    if n == 0 && m == 0 {
        return Vec::new();
    }
    // LCS length table.
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if al[i] == bl[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if al[i] == bl[j] {
            ops.push(DiffOp::Same(al[i].to_string()));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(DiffOp::Del(al[i].to_string()));
            i += 1;
        } else {
            ops.push(DiffOp::Add(bl[j].to_string()));
            j += 1;
        }
    }
    while i < n {
        ops.push(DiffOp::Del(al[i].to_string()));
        i += 1;
    }
    while j < m {
        ops.push(DiffOp::Add(bl[j].to_string()));
        j += 1;
    }
    ops
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_diff() {
        let ops = diff_lines("a\nb\nc", "a\nx\nc\nd");
        assert!(ops.contains(&DiffOp::Same("a".into())));
        assert!(ops.contains(&DiffOp::Del("b".into())));
        assert!(ops.contains(&DiffOp::Add("x".into())));
        assert!(ops.contains(&DiffOp::Add("d".into())));
    }

    #[test]
    fn empty_inputs() {
        assert!(diff_lines("", "").is_empty());
        assert_eq!(diff_lines("", "a"), vec![DiffOp::Add("a".into())]);
    }
}
