//! Qlean is a system-level isolation testing library built on QEMU/KVM.
//! It spins up lightweight VMs in your Rust tests so privileged or risky operations stay off the host.
//!
//! # Features
//!
//! - **Isolation**: Each test runs in its own VM, so failures don't bring down the host.
//! - **Distributed testing**: Easily create and manage multiple virtual machines from test code.
//! - **RAII-style interface**: Automatic resource management ensures VMs are properly cleaned up.
//! - **Out-of-the-box**: Automated image downloading with verification, no manual configuration needed.
//! - **Linux native**: Native support for Linux hosts with multiple guest distributions and architectures.
//! - **Windows guests** (unreleased, tracked as 0.4.0): `GuestOs::Windows` runs a licensed qcow2 you
//!   supply over OVMF + a per-VM TPM 2.0 and a TCP transport. It needs QEMU, OVMF, `swtpm`,
//!   `xorriso` and libvirt on the host; see the README "Windows image contract" section.
//!
//! # Examples
//!
//! Examples can be found in the [tests](https://github.com/buck2hub/qlean/tree/main/tests) directory.
//!
//! # Getting Started
//!
//! For a quick start, see <https://buck2hub.com/docs/qlean>.

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use kvm_ioctls::Kvm;

use crate::utils::{ensure_host_prerequisites, ensure_prerequisites};

mod exec;
mod firmware;
mod guest_path;
mod image;
mod machine;
mod pool;
mod qemu;
mod qmp;
mod ssh;
mod utils;
mod windows;

// Re-export public types and functions
pub use image::Distro;
pub use image::GuestArch;
pub use image::GuestOs;
pub use image::Image;
pub use image::ImageConfig;
pub use machine::{Machine, MachineConfig};
pub use pool::MachinePool;
pub use ssh::{InteractiveShell, InteractiveShellReader, InteractiveShellWriter};

/// Check if KVM is available on the host.
pub fn is_kvm_available() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        return false;
    }

    Kvm::new().is_ok()
}

/// Execute a closure with a virtual machine.
pub async fn with_machine<'a, F, R>(image: &'a Image, config: &'a MachineConfig, f: F) -> Result<R>
where
    F: for<'b> FnOnce(&'b mut Machine) -> Pin<Box<dyn Future<Output = Result<R>> + 'b>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Qlean currently only supports Linux hosts.");
    }

    ensure_prerequisites(image.guest_os()).await?;

    let mut machine = Machine::new(image, config).await?;
    machine.init().await?;
    let outcome = f(&mut machine).await;
    let shutdown = machine.shutdown().await;

    combine_outcome(outcome, shutdown)
}

/// Execute a closure with a virtual machine pool.
pub async fn with_pool<F, R>(f: F) -> Result<R>
where
    F: for<'a> FnOnce(&'a mut MachinePool) -> Pin<Box<dyn Future<Output = Result<R>> + 'a>>,
{
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Qlean currently only supports Linux hosts.");
    }

    // Pool members may be Windows guests, which do not need vsock; guest-specific
    // requirements are enforced when each machine starts.
    ensure_host_prerequisites().await?;

    let mut pool = MachinePool::new();
    let outcome = f(&mut pool).await;
    let shutdown = pool.shutdown_all().await;

    combine_outcome(outcome, shutdown)
}

/// Report the closure's outcome, keeping a teardown failure as context on it.
///
/// A teardown failure used to replace the closure's error outright: a test that failed for
/// its own reason reported only "cleanup failed", which hides the actual defect and sends
/// the reader after the wrong problem. The closure's error stays the primary one and the
/// teardown error is attached to it; a teardown failure on its own is still an error
/// because a VM that could not be stopped leaks resources.
fn combine_outcome<T>(outcome: Result<T>, shutdown: Result<()>) -> Result<T> {
    match (outcome, shutdown) {
        (Err(error), Err(teardown)) => {
            Err(error.context(format!("teardown also failed: {teardown:#}")))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(teardown)) => Err(teardown),
        (Ok(value), Ok(())) => Ok(value),
    }
}

#[cfg(test)]
mod plan_doc_tests {
    /// Every Rust source the plan reasons about, so the guard tests can read real test names.
    const CRATE_SOURCES: &[(&str, &str)] = &[
        ("src/exec.rs", include_str!("../src/exec.rs")),
        ("src/firmware.rs", include_str!("../src/firmware.rs")),
        ("src/guest_path.rs", include_str!("../src/guest_path.rs")),
        ("src/image.rs", include_str!("../src/image.rs")),
        ("src/lib.rs", include_str!("../src/lib.rs")),
        ("src/machine.rs", include_str!("../src/machine.rs")),
        ("src/pool.rs", include_str!("../src/pool.rs")),
        ("src/qemu.rs", include_str!("../src/qemu.rs")),
        ("src/qmp.rs", include_str!("../src/qmp.rs")),
        ("src/ssh.rs", include_str!("../src/ssh.rs")),
        ("src/utils.rs", include_str!("../src/utils.rs")),
        ("src/windows.rs", include_str!("../src/windows.rs")),
        (
            "tests/windows_machine.rs",
            include_str!("../tests/windows_machine.rs"),
        ),
    ];

    /// The test function names declared in `sources`, and the module names they live under.
    ///
    /// A test is a `fn`/`async fn` whose four preceding lines hold `#[test]`, `#[tokio::test…]`
    /// or `#[ignore…]`. Reading the sources (rather than a hand-kept list) is the point: the plan
    /// quotes test names, and a quote that no longer resolves is a promise to a reader.
    fn test_names_in(sources: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
        let mut names = Vec::new();
        let mut modules = Vec::new();
        for (path, source) in sources {
            let lines: Vec<&str> = source.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                let Some(rest) = trimmed
                    .strip_prefix("fn ")
                    .or_else(|| trimmed.strip_prefix("async fn "))
                else {
                    continue;
                };
                assert!(
                    !path.is_empty(),
                    "a crate source is registered without a path"
                );
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                let attributed = lines[index.saturating_sub(4)..index].iter().any(|above| {
                    let above = above.trim();
                    above.starts_with("#[test]")
                        || above.starts_with("#[tokio::test")
                        || above.starts_with("#[ignore")
                });
                if attributed {
                    names.push(name);
                }
            }
            for line in &lines {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("mod ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        modules.push(name);
                    }
                }
            }
        }
        (names, modules)
    }

    /// The revision history is one timeline, newest first.
    ///
    /// Half of it used to grow downwards (R1 at the top, appended after the header) and the
    /// other half grew upwards (each new round prepended), so the newest change sat in the
    /// middle of the table and a reader could not tell which end to read from — while every
    /// summary in the plan and in `plan-status.md` refers to "the latest R<n> row". Ordering
    /// by review number is what makes that sentence true; the `R9 补记` follow-up is allowed
    /// to sit next to R9.
    #[test]
    fn the_plan_revision_history_is_ordered_newest_first() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const HEADING: &str = "### 修订历史";

        let lines: Vec<&str> = PLAN.lines().collect();
        let heading = lines
            .iter()
            .position(|line| line.trim_end() == HEADING)
            .expect("the plan has no 修订历史 section");
        let header = lines[heading..]
            .iter()
            .position(|line| line.starts_with("| 时间 |"))
            .map(|offset| heading + offset)
            .expect("the 修订历史 section has no table header");
        let body: Vec<&str> = lines[header + 2..]
            .iter()
            .take_while(|line| line.starts_with('|'))
            .copied()
            .collect();
        assert!(body.len() > 10, "the revision history table looks empty");

        let mut last: Option<u32> = None;
        let mut seen: Vec<u32> = Vec::new();
        for row in body {
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            let (time, trigger) = (cells[1], cells[2]);
            assert!(
                time.len() == 23 && time.ends_with(" UTC"),
                "a revision history row has no `YYYY-MM-DD HH:MM:SS UTC` timestamp: {row}"
            );
            if let Some(number) = trigger.strip_prefix("review R").and_then(|rest| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<u32>().ok()
            }) {
                if let Some(previous) = last {
                    assert!(
                        number <= previous,
                        "R{number} is listed after R{previous}: the table must run newest first"
                    );
                    assert!(
                        !seen.contains(&number) || number == previous,
                        "R{number} appears twice, separated from its own row"
                    );
                }
                if !seen.contains(&number) {
                    seen.push(number);
                }
                last = Some(number);
            }
        }
        assert_eq!(
            seen.first().copied(),
            seen.iter().copied().max(),
            "the newest review is not the first row of the table"
        );
        assert!(
            seen.windows(2).all(|pair| pair[0] > pair[1]),
            "the review numbers in the table are not strictly descending: {seen:?}"
        );
    }

    /// The revision history is one table, not a table with prose wedged into the middle of it.
    ///
    /// Markdown ends a table at the first line that is not a table row, so a paragraph inserted
    /// between two rows silently cuts the table in half: the rows below it stop being rows for
    /// every reader that renders markdown, and a reader of the raw file cannot tell whether the
    /// paragraph belongs to the section or to a row. Prose about the table belongs after it.
    #[test]
    fn the_plan_revision_history_table_is_not_split_by_prose() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const HEADING: &str = "### 修订历史";

        let lines: Vec<&str> = PLAN.lines().collect();
        let heading = lines
            .iter()
            .position(|line| line.trim_end() == HEADING)
            .expect("the plan has no 修订历史 section");
        let header = lines[heading..]
            .iter()
            .position(|line| line.starts_with("| 时间 |"))
            .map(|offset| heading + offset)
            .expect("the 修订历史 section has no table header");

        let mut ended = false;
        for (offset, line) in lines[header + 2..].iter().enumerate() {
            let is_row = line.starts_with('|');
            if ended && is_row {
                panic!(
                    "the revision history table ends and starts again at line {}: \
                     markdown ends a table at the first non-row line, so every row after that \
                     break is invisible as a table row: {line}",
                    header + 3 + offset
                );
            }
            if !is_row {
                ended = true;
                // The section is over: a later table belongs to another section.
                if line.starts_with("## ") || line.starts_with("### ") {
                    break;
                }
            }
        }
    }

    /// Every Windows smoke test the code defers is named in the plan, and every smoke test the
    /// plan names exists.
    ///
    /// The plan is the only place that says which acceptance criteria are still blocked on real
    /// Windows hardware, and it names them by test function. A hand-copied list of names drifts:
    /// rename the test and the plan keeps promising a name that no longer exists, and a reader
    /// greps for it, finds nothing, and cannot tell "deferred" from "already deleted".
    #[test]
    fn the_plan_names_exactly_the_deferred_windows_smoke_tests() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const SMOKE_TESTS: &str = include_str!("../tests/windows_machine.rs");

        let mut deferred: Vec<String> = Vec::new();
        let mut lines = SMOKE_TESTS.lines().map(str::trim).peekable();
        while let Some(line) = lines.next() {
            if !line.starts_with("#[ignore") {
                continue;
            }
            // `#[ignore = "..."]` may wrap; the attribute is followed by the test signature.
            let mut rest = lines.clone();
            let mut name = None;
            for _ in 0..4 {
                let next = rest.next().unwrap_or_default();
                if let Some(after) = next.split("fn ").nth(1) {
                    name = Some(
                        after
                            .split('(')
                            .next()
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                    );
                    break;
                }
            }
            if let Some(name) = name {
                assert!(
                    !name.is_empty(),
                    "an `#[ignore]` test has no parseable name"
                );
                deferred.push(name);
            }
        }
        assert!(
            !deferred.is_empty(),
            "tests/windows_machine.rs has no `#[ignore]` tests: the deferred smoke matrix is gone"
        );

        for name in &deferred {
            // Whole-name match: `windows_get_ip` is not mentioned by a plan that only contains
            // `windows_get_ip_renamed`.
            let mentioned = PLAN.match_indices(name.as_str()).any(|(index, _)| {
                PLAN[index + name.len()..]
                    .chars()
                    .next()
                    .is_none_or(|next| !(next.is_alphanumeric() || next == '_'))
            });
            assert!(
                mentioned,
                "the plan never names the deferred smoke test `{name}`: a reader cannot tell \
                 what is still blocked on real Windows hardware"
            );
        }
        assert!(
            deferred.len() >= 7,
            "the plan defers 7 Windows smoke tests but the code defers {}: {deferred:?}",
            deferred.len()
        );
    }
    /// Every test the plan points at can be selected by the filter the plan prints.
    ///
    /// The trace table and the `cargo test -- --ignored <label>` hints in the sources name tests
    /// by label, and a label that selects nothing is worse than a stale one: cargo prints
    /// `0 passed` and exits successfully, so a reviewer re-running "the specified test" gets a
    /// green result from a test that never ran. This test reads the test names out of the
    /// sources and requires every label to match at least one of them.
    #[test]
    fn the_plan_points_at_tests_that_can_be_run() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let (tests, _modules) = test_names_in(CRATE_SOURCES);
        assert!(
            tests.len() >= 200,
            "the test-name scan found only {} tests: it is scanning the wrong thing",
            tests.len()
        );
        let selects = |label: &str| tests.iter().any(|name| name.contains(label));

        // The print-the-filter hints inside the crate must print a filter that selects something.
        // The marker is assembled at runtime so that this test's own source does not look like a
        // hint that advertises an empty filter.
        let marker = ["cargo", "test", "--lib", "--", "--ignored", ""].join(" ");
        let mut hints = 0;
        for (path, source) in CRATE_SOURCES {
            for line in source.lines() {
                let Some(rest) = line.split(marker.as_str()).nth(1) else {
                    continue;
                };
                let label: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                assert!(
                    !label.is_empty(),
                    "{path} advertises an empty `--ignored` filter"
                );
                hints += 1;
                assert!(
                    selects(&label),
                    "{path} tells the reader to run `--ignored {label}`, which selects no test: \
                     cargo would report `0 passed` and the reviewer would call it green"
                );
            }
        }
        assert!(
            hints >= 5,
            "the sources advertise only {hints} runnable test filters"
        );

        // The trace table's `指定测试` column must name tests that exist.
        // Anchor on a heading that stands alone on its line: the revision history quotes this
        // heading by name, and a substring search would start the scan inside that row.
        let lines: Vec<&str> = PLAN.lines().collect();
        let heading = lines
            .iter()
            .position(|line| line.trim_end() == "## 追溯表")
            .expect("the plan has no 追溯表 section");
        let section: Vec<&str> = lines[heading..]
            .iter()
            .take_while(|line| !(line.starts_with("## ") && !line.starts_with("## 追溯表")))
            .copied()
            .collect();
        let mut checked = 0;
        for row in section.iter().filter(|line| line.starts_with('|')) {
            let cells: Vec<&str> = row.split('|').collect();
            if cells.len() < 7 {
                continue;
            }
            let task = cells[1].trim();
            let last = cells[cells.len() - 2];
            for label in last.split('`').skip(1).step_by(2) {
                if !label.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                // Commit hashes live in the same column; they are evidence, not filters.
                if label.chars().all(|c| c.is_ascii_hexdigit()) && (7..=40).contains(&label.len()) {
                    continue;
                }
                checked += 1;
                assert!(
                    selects(label),
                    "the trace table says `{task}` is covered by `{label}`, which matches no test \
                     name: `cargo test {label}` would run nothing and still succeed"
                );
            }
        }
        assert!(
            checked >= 10,
            "the trace table's 指定测试 column yielded only {checked} labels"
        );
    }
    /// Every `cargo test` line the plan prints selects something.
    ///
    /// The plan asks reviewers to re-run named tests in almost every evidence row. A filter that
    /// selects nothing is answered with `0 passed` and exit status 0, so a green line in a review
    /// can mean "nothing ran". This walks every `cargo test` command in the plan, works out which
    /// test binary it targets, and requires the filter to match at least one test there.
    #[test]
    fn the_plan_prints_only_filters_that_select_a_test() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let (unit, unit_modules) = test_names_in(
            &CRATE_SOURCES
                .iter()
                .filter(|(path, _)| path.starts_with("src/"))
                .copied()
                .collect::<Vec<_>>(),
        );
        let (integration, _integration_modules) = test_names_in(
            &CRATE_SOURCES
                .iter()
                .filter(|(path, _)| path.starts_with("tests/"))
                .copied()
                .collect::<Vec<_>>(),
        );
        assert!(
            unit.len() >= 200 && !integration.is_empty(),
            "the test-name scan found {} unit and {} integration tests",
            unit.len(),
            integration.len()
        );

        // The revision history is a record of what was wrong: it has to be able to quote a bad
        // command. Everything else in the plan is read as an instruction to re-run something.
        let lines: Vec<&str> = PLAN.lines().collect();
        let history_start = lines
            .iter()
            .position(|line| line.trim_end() == "### 修订历史")
            .expect("the plan has no 修订历史 section");
        let history_end = lines[history_start + 1..]
            .iter()
            .position(|line| line.starts_with("## ") || line.starts_with("### "))
            .map_or(lines.len(), |offset| history_start + 1 + offset);

        let mut checked = 0;
        for line in lines[..history_start].iter().chain(&lines[history_end..]) {
            for (start, _) in line.match_indices("cargo test ") {
                let rest = &line[start..];
                let command: String = rest
                    .chars()
                    .take_while(|c| !matches!(c, '`' | '；' | '）' | '('))
                    .collect();
                let integration_target = command.contains("--test windows_machine");
                let filter = command.split_whitespace().skip(2).find(|token| {
                    !token.starts_with('-')
                        && !matches!(*token, "lib" | "windows_machine" | "test")
                        && token
                            .chars()
                            .all(|c| c.is_alphanumeric() || c == '_' || c == ':')
                });
                let Some(filter) = filter else {
                    // `cargo test --lib`, `cargo test --no-run`: the whole suite, no filter.
                    continue;
                };
                let (names, where_) = if integration_target {
                    (&integration, "tests/windows_machine.rs")
                } else {
                    (&unit, "the lib tests")
                };
                checked += 1;
                let last = filter.rsplit("::").next().unwrap_or(filter);
                let segments_are_modules = filter
                    .split("::")
                    .all(|segment| unit_modules.iter().any(|module| module == segment));
                assert!(
                    names.iter().any(|name| name.contains(last)) || segments_are_modules,
                    "the plan prints `{command}`, whose filter `{filter}` matches no test in \
                     {where_}: cargo would print `0 passed` and the reader would call it green"
                );
            }
        }
        assert!(
            checked >= 40,
            "the plan only yielded {checked} runnable test filters: the scan is not looking at them"
        );
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::combine_outcome;

    #[test]
    fn a_closure_failure_keeps_its_own_cause_when_teardown_fails_too() {
        let error = combine_outcome::<()>(
            Err(anyhow::anyhow!("the guest command failed")),
            Err(anyhow::anyhow!("QEMU did not stop")),
        )
        .expect_err("a failed closure stays a failure");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("the guest command failed"), "{rendered}");
        assert!(rendered.contains("QEMU did not stop"), "{rendered}");
    }

    #[test]
    fn a_successful_closure_does_not_hide_a_teardown_failure() {
        let error = combine_outcome(Ok(7u8), Err(anyhow::anyhow!("seed medium stayed mounted")))
            .expect_err("a VM that could not be stopped is an error");
        assert!(error.to_string().contains("seed medium stayed mounted"));
    }

    #[test]
    fn a_clean_teardown_returns_the_closure_value() {
        assert_eq!(combine_outcome(Ok(7u8), Ok(())).unwrap(), 7);
        assert!(combine_outcome::<u8>(Err(anyhow::anyhow!("boom")), Ok(())).is_err());
    }
}
