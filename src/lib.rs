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

    /// The `<n>` of the first `<n> passed` in `text`, if the text carries one.
    fn claimed_passes(text: &str) -> Option<usize> {
        let marker = " passed";
        let mut search = 0;
        while let Some(found) = text[search..].find(marker) {
            let at = search + found;
            let digits: String = text[..at]
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<Vec<char>>()
                .into_iter()
                .rev()
                .collect();
            if !digits.is_empty() {
                return digits.parse().ok();
            }
            search = at + marker.len();
        }
        None
    }

    /// The tests declared in `sources`, as full paths such as `image::tests::test_the_guard`.
    ///
    /// A test is a `fn`/`async fn` whose four preceding lines hold `#[test]`, `#[tokio::test…]`
    /// or `#[ignore…]`. Reading the sources (rather than a hand-kept list) is the point: the plan
    /// quotes test names, and a quote that no longer resolves is a promise to a reader. Module
    /// paths come from indentation, which is what `cargo fmt` keeps stable.
    fn test_names_in(sources: &[(&str, &str)]) -> Vec<String> {
        let mut tests = Vec::new();
        for (path, source) in sources {
            assert!(
                !path.is_empty(),
                "a crate source is registered without a path"
            );
            // cargo names a test after the module the file is in, so `src/image.rs` contributes
            // `image::` and the crate root contributes nothing.
            let file_module = path
                .strip_prefix("src/")
                .and_then(|rest| rest.strip_suffix(".rs"))
                .filter(|rest| *rest != "lib")
                .map(|rest| rest.replace('/', "::"));
            let lines: Vec<&str> = source.lines().collect();
            let mut modules: Vec<(usize, String)> = Vec::new();
            for (index, line) in lines.iter().enumerate() {
                let trimmed = line.trim();
                let indent = line.len() - line.trim_start().len();
                if trimmed == "}" {
                    while modules.last().is_some_and(|(inner, _)| *inner >= indent) {
                        modules.pop();
                    }
                    continue;
                }
                if let Some(rest) = trimmed
                    .strip_prefix("pub mod ")
                    .or_else(|| trimmed.strip_prefix("pub(crate) mod "))
                    .or_else(|| trimmed.strip_prefix("mod "))
                {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() && trimmed.ends_with('{') {
                        while modules.last().is_some_and(|(inner, _)| *inner >= indent) {
                            modules.pop();
                        }
                        modules.push((indent, name));
                    }
                    continue;
                }
                let Some(rest) = trimmed
                    .strip_prefix("fn ")
                    .or_else(|| trimmed.strip_prefix("async fn "))
                else {
                    continue;
                };
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
                    let mut full = String::new();
                    if let Some(module) = &file_module {
                        full.push_str(module);
                        full.push_str("::");
                    }
                    for (_, module) in &modules {
                        full.push_str(module);
                        full.push_str("::");
                    }
                    full.push_str(&name);
                    tests.push(full);
                }
            }
        }
        tests
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

        let tests = test_names_in(CRATE_SOURCES);
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
    /// The push backlog is one number, whichever document states it.
    ///
    /// Two documents describe the same blocked dependency: the plan's dependency registry says how
    /// far `main` is ahead of the remote, and the status view says how many commits the eventual
    /// push will carry. Both are hand-typed after each `libra push` failure, and a reader planning
    /// the release reads whichever they find first. Neither number can be checked from inside a
    /// test - only that they agree - so that is what this asserts, along with the retest stamp they
    /// both claim.
    #[test]
    fn the_push_backlog_is_stated_once() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");

        fn registry(plan: &str) -> Vec<&str> {
            let lines: Vec<&str> = plan.lines().collect();
            let start = lines
                .iter()
                .position(|line| line.trim_end() == "### 依赖登记表")
                .expect("the plan has no dependency registry");
            let end = lines[start + 1..]
                .iter()
                .position(|line| line.starts_with("### "))
                .map(|offset| start + 1 + offset)
                .expect("the dependency registry is the last section of its level");
            lines[start..end].to_vec()
        }

        fn backlog<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
            let at = text.find(marker)?;
            let after = &text[at + marker.len()..];
            let digits: &str = after.split(|c: char| !c.is_ascii_digit()).next()?;
            (!digits.is_empty()).then_some(digits)
        }

        let plan_registry = registry(PLAN).join("\n");
        let status_row = STATUS
            .lines()
            .find(|line| line.starts_with("| DEP-03 |"))
            .expect("the status view has no DEP-03 row");
        let plan_row = plan_registry
            .lines()
            .find(|line| line.starts_with("| DEP-03 |"))
            .expect("the plan registry has no DEP-03 row");

        let stated = [
            ("the plan", plan_row, "领先远端 "),
            ("the status view", status_row, "届时推送 "),
        ];
        let counts: Vec<(&str, &str)> = stated
            .iter()
            .map(|(who, row, marker)| {
                (
                    *who,
                    backlog(row, marker).unwrap_or_else(|| {
                        panic!("{who} no longer states the push backlog as `{marker}N 个提交`")
                    }),
                )
            })
            .collect();
        for (who, count) in &counts[1..] {
            assert_eq!(
                *count, counts[0].1,
                "{who} says the backlog is {count} commits but {} says {}: one push, two numbers",
                counts[0].0, counts[0].1
            );
        }

        fn first_stamp(row: &str) -> &str {
            let at = row
                .find(" UTC 复测")
                .unwrap_or_else(|| panic!("a DEP-03 row carries no retest stamp: {row}"));
            let start = row[..at]
                .rfind(|c: char| !c.is_ascii_digit() && c != '-')
                .map(|index| index + 1)
                .unwrap_or(0);
            &row[start..at]
        }
        assert_eq!(
            first_stamp(status_row),
            first_stamp(plan_row),
            "the two DEP-03 rows describe retests at different times, so one of them is stale"
        );
    }

    /// The changelog's newest release is the version the crate is, dated, and in order.
    ///
    /// A version lives in three places: `Cargo.toml`, the README's support matrix and the
    /// changelog. Bumping one and not the others is how a release ends up announcing a version
    /// whose notes are still under `Unreleased`. The date and the ordering are here because a
    /// release heading that is undated, or a list that runs backwards, is the same kind of drift
    /// in the same file.
    #[test]
    fn the_changelog_releases_the_version_the_crate_is() {
        const CHANGELOG: &str = include_str!("../CHANGELOG.md");
        let version = env!("CARGO_PKG_VERSION");

        let mut releases: Vec<(u64, u64, u64, String)> = Vec::new();
        for line in CHANGELOG.lines() {
            let Some(rest) = line.strip_prefix("## [") else {
                continue;
            };
            let (name, tail) = rest
                .split_once(']')
                .unwrap_or_else(|| panic!("a changelog heading has no closing bracket: {line}"));
            if name == "Unreleased" {
                continue;
            }
            let parts: Vec<u64> = name
                .split('.')
                .map(|part| {
                    part.parse()
                        .unwrap_or_else(|_| panic!("a changelog version is not numeric: {line}"))
                })
                .collect();
            assert_eq!(parts.len(), 3, "a changelog version is not x.y.z: {line}");
            let date = tail
                .trim()
                .strip_prefix("- ")
                .unwrap_or_else(|| panic!("a changelog release is undated: {line}"));
            assert!(
                date.len() == 10 && date.as_bytes()[4] == b'-' && date.as_bytes()[7] == b'-',
                "a changelog release carries a date that is not YYYY-MM-DD: {line}"
            );
            releases.push((parts[0], parts[1], parts[2], name.to_string()));
        }
        assert!(
            releases.len() >= 5,
            "the changelog lists only {} releases",
            releases.len()
        );
        assert_eq!(
            releases[0].3, version,
            "the changelog's newest release is {}, but the crate is {version}: bumping one without \
             the other announces a version whose notes are still unreleased",
            releases[0].3
        );
        for window in releases.windows(2) {
            assert!(
                (window[0].0, window[0].1, window[0].2) > (window[1].0, window[1].1, window[1].2),
                "the changelog lists {} above {}, so it reads backwards",
                window[0].3,
                window[1].3
            );
        }
    }

    /// Every `QLEAN_*` override the crate reads is named in the README.
    ///
    /// The overrides are the only way to point the crate at a different OVMF, swtpm or timeout
    /// without recompiling, so an override nobody documented is an override nobody can use - and
    /// the failure is silent, because the code keeps working for whoever wrote it. Test hooks are
    /// the exception, and they are named here so adding one stays a decision rather than a leak.
    #[test]
    fn every_environment_override_the_crate_reads_is_documented() {
        const README: &str = include_str!("../README.md");
        // Test hooks: they take effect only inside a test that asks for them.
        const TEST_HOOKS: &[&str] = &["QLEAN_REFUSED_KILL_PID"];

        let mut read: Vec<&str> = Vec::new();
        for (path, source) in CRATE_SOURCES {
            if !path.starts_with("src/") {
                continue;
            }
            let mut rest = *source;
            while let Some(at) = rest.find("\"QLEAN_") {
                let after = &rest[at + 1..];
                let end = after.find('"').expect("an override name is not closed");
                read.push(&after[..end]);
                rest = &after[end..];
            }
        }
        read.sort_unstable();
        read.dedup();
        assert!(
            read.len() >= 4,
            "the crate reads only {} QLEAN_ overrides",
            read.len()
        );

        for name in read {
            if TEST_HOOKS.contains(&name) {
                continue;
            }
            assert!(
                README.contains(name),
                "the crate reads {name} but the README never mentions it, so only its author \
                 knows it exists"
            );
        }
    }

    /// The plan keeps every section the template makes mandatory.
    ///
    /// The template's rule is that mandatory sections may not be dropped - a section that does not
    /// apply is written `N/A` instead. Nothing enforced that against the plan, and the plan had
    /// already lost one: the three subsections under `文档职责` were all present, but their heading
    /// was not, so a reader (or a grep for the section) saw no document-responsibility section at
    /// all. Deriving the list from the template means a template change reaches this check.
    #[test]
    fn the_plan_keeps_every_section_the_template_requires() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const TEMPLATE: &str = include_str!("../docs/plan/plan-template.md");

        // Sections that describe the template itself, not a plan.
        const TEMPLATE_ONLY: &[&str] = &["使用规则", "标题"];

        let required: Vec<&str> = TEMPLATE
            .lines()
            .filter_map(|line| line.strip_prefix("## "))
            .map(str::trim)
            .filter(|title| !TEMPLATE_ONLY.contains(title))
            .collect();
        assert!(
            required.len() > 15,
            "the template yielded only {} mandatory sections",
            required.len()
        );

        let headings: Vec<&str> = PLAN
            .lines()
            .filter_map(|line| line.strip_prefix("## "))
            .map(str::trim)
            .collect();
        for title in &required {
            assert!(
                headings.contains(title),
                "the plan has no `## {title}` section, though the template makes it mandatory"
            );
        }
    }

    /// Every card carries the fields the template makes mandatory, with a value in each.
    ///
    /// The fields are what makes a card executable on its own: its type, its state, how to undo it,
    /// what it may write, whether it bumps the version, what it inherits and how it splits. A card
    /// missing one of them reads as if that question had no answer, and the plan's own granularity
    /// audit table would not notice.
    #[test]
    fn every_card_carries_the_fields_the_template_requires() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const FIELDS: &[&str] = &[
            "**Task type:**",
            "**Lifecycle / Acceptance:**",
            "**Rollback mode:**",
            "**Implementation write set:**",
            "**Version increment:**",
            "**C/D coverage from:**",
            "**Granularity:**",
            "**Deliverables:**",
            "**Docs and compatibility impact:**",
        ];

        let mut cards = 0;
        let mut current: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();

        let check = |id: &str, seen: &Vec<String>| {
            for field in FIELDS {
                let value = seen
                    .iter()
                    .find_map(|line| line.strip_prefix(field))
                    .unwrap_or_else(|| panic!("card {id} has no {field} line"));
                assert!(
                    !value.trim().is_empty(),
                    "card {id} leaves {field} empty instead of writing N/A and why"
                );
            }
        };

        for line in PLAN.lines() {
            if let Some(rest) = line.strip_prefix("### Task ") {
                if let Some(id) = current.as_deref() {
                    check(id, &seen);
                }
                current = Some(rest.split(':').next().unwrap_or(rest).trim().to_string());
                seen.clear();
                cards += 1;
                continue;
            }
            if line.starts_with("## ") || line.starts_with("### ") {
                if let Some(id) = current.as_deref() {
                    check(id, &seen);
                }
                current = None;
                seen.clear();
                continue;
            }
            if current.is_some() && line.starts_with("**") {
                seen.push(line.to_string());
            }
        }
        if let Some(id) = current.as_deref() {
            check(id, &seen);
        }
        assert_eq!(cards, 10, "the plan declares {cards} cards");
    }

    /// The status view repeats the lifecycle each card declares, not one of its own.
    ///
    /// A card states its state in two places: its own `Lifecycle / Acceptance` line, which the
    /// plan calls authoritative, and the summary table in `plan-status.md`. Two hand-kept copies of
    /// the same token drift the moment one is updated alone, and the resolution rule in the status
    /// view only says which one wins - it does not notice that they disagreed.
    #[test]
    fn the_status_view_repeats_the_lifecycle_each_card_declares() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");

        let mut cards: Vec<(String, String, String)> = Vec::new();
        let mut current: Option<String> = None;
        for line in PLAN.lines() {
            if let Some(rest) = line.strip_prefix("### Task ") {
                current = Some(rest.split(':').next().unwrap_or(rest).trim().to_string());
                continue;
            }
            if line.starts_with("## ") {
                current = None;
                continue;
            }
            let Some(rest) = line.strip_prefix("**Lifecycle / Acceptance:**") else {
                continue;
            };
            let id = current
                .clone()
                .unwrap_or_else(|| panic!("a lifecycle line sits outside a card: {line}"));
            let lifecycle = rest
                .trim_start()
                .strip_prefix('`')
                .and_then(|tail| tail.split('`').next())
                .unwrap_or_else(|| panic!("card {id} states no lifecycle token: {line}"));
            let acceptance = rest
                .trim_start()
                .split_once('/')
                .map(|(_, tail)| tail)
                .unwrap_or_else(|| panic!("card {id} states no acceptance token: {line}"))
                .trim_start()
                .trim_start_matches('`')
                .chars()
                .take_while(|c| !matches!(c, '`' | '（' | '(' | ' '))
                .collect::<String>();
            assert!(
                !acceptance.is_empty(),
                "card {id} states an empty acceptance token: {line}"
            );
            cards.push((id, lifecycle.to_string(), acceptance));
        }
        assert_eq!(cards.len(), 10, "the plan declares {} cards", cards.len());

        for (id, lifecycle, acceptance) in &cards {
            let row = STATUS
                .lines()
                .find(|line| line.starts_with(&format!("| {id} |")))
                .unwrap_or_else(|| panic!("the status view has no row for {id}"));
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            assert!(
                cells.len() > 4,
                "the status row for {id} lost its columns: {row}"
            );
            assert_eq!(
                (cells[3], cells[4]),
                (lifecycle.as_str(), acceptance.as_str()),
                "card {id} declares {lifecycle} / {acceptance} but the status view says {} / {}",
                cells[3],
                cells[4]
            );
        }
    }

    /// The README states the version the crate is, not the version it used to be.
    ///
    /// The support matrix names a released version so a reader can tell what the claim covers.
    /// Nothing keeps that number honest: bump `Cargo.toml` and the README goes on describing the
    /// previous release as current, which is the one line a reader trusts most.
    #[test]
    fn the_readme_states_the_version_the_crate_is() {
        const README: &str = include_str!("../README.md");
        let version = env!("CARGO_PKG_VERSION");

        let mut stated = Vec::new();
        let mut rest = README;
        while let Some(at) = rest.find("released (`") {
            let after = &rest[at + "released (`".len()..];
            let end = after.find('`').expect("a released version is not closed");
            stated.push(&after[..end]);
            rest = &after[end..];
        }
        assert!(
            !stated.is_empty(),
            "the README no longer names a released version in its support matrix"
        );
        for claim in stated {
            assert_eq!(
                claim, version,
                "the README calls {claim} the released version, but the crate is {version}"
            );
        }
    }

    /// The README does not claim Windows support while the smoke tests that would earn it are
    /// deferred.
    ///
    /// The plan forbids announcing Windows support without recorded evidence from a real KVM host.
    /// The smoke tests are ignored for exactly that reason, so their `#[ignore]` attributes
    /// and the README's "Claimed support" column are the same fact written twice. Flipping the
    /// column to yes is the mistake a release would make; this catches it.
    #[test]
    fn the_readme_claims_no_windows_support_while_the_smoke_tests_are_deferred() {
        const README: &str = include_str!("../README.md");
        const SMOKE_TESTS: &str = include_str!("../tests/windows_machine.rs");

        // Count attributes, not mentions: the file also says `#[ignore]`d in its own prose.
        let deferred = SMOKE_TESTS
            .lines()
            .filter(|line| line.starts_with("#[ignore"))
            .count();
        assert!(
            deferred > 0,
            "no Windows smoke test is deferred any more: the README's support claim has to be \
             re-decided by hand before this guard is relaxed"
        );

        let row = README
            .lines()
            .find(|line| line.starts_with("| Windows 10 / 11"))
            .expect("the README support matrix has no Windows row");
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        assert!(
            cells.len() > 3,
            "the Windows row of the support matrix lost its columns: {row}"
        );
        assert_eq!(
            cells[3], "**no**",
            "the README claims Windows support while {deferred} smoke tests are still deferred: \
             the claim needs recorded KVM evidence, not a table edit"
        );
    }

    /// The status view names the newest review round, so the two documents agree on where work
    /// stopped.
    ///
    /// `plan-status.md` exists so a reader has one place to learn how far the plan has got. It is
    /// updated by hand every round, and the failure mode is silent: the plan keeps growing while
    /// the status view quietly stops one round short, and the reader takes the stale round for the
    /// current one.
    #[test]
    fn the_status_view_is_not_behind_the_plan() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");

        let lines: Vec<&str> = PLAN.lines().collect();
        let heading = lines
            .iter()
            .position(|line| line.trim_end() == "## Review log")
            .expect("the plan has no Review log section");
        let planned = lines[heading + 1..]
            .iter()
            .take_while(|line| !line.starts_with("## "))
            .filter_map(|line| line.strip_prefix("| R"))
            .map(|rest| {
                rest.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
            })
            .filter(|digits| !digits.is_empty())
            .filter_map(|digits| digits.parse::<u32>().ok())
            .max()
            .expect("the review log has no rounds");

        let reported = STATUS
            .match_indices('R')
            .filter_map(|(at, _)| {
                let digits: String = STATUS[at + 1..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                digits.parse::<u32>().ok()
            })
            .max()
            .expect("the status view names no review round");

        assert_eq!(
            reported, planned,
            "the plan's newest round is R{planned} but the status view stops at R{reported}: \
             a reader would take the stale round for the current one"
        );
    }

    /// Every round in the review log that can name its commit does name one.
    ///
    /// The log's whole value is that a reader can walk from a round number to the code. Ten early
    /// rounds cannot: they were written before the rule existed and the commits behind them were
    /// never recorded, so filling them in now would be a guess. That set is fixed and small. Any
    /// other row without a hash is a row nobody can follow - including the docs-only rounds, whose
    /// own documentation commit is the thing to cite.
    #[test]
    fn the_review_log_names_a_commit_for_every_round_it_can() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const UNRECORDED: &[u32] = &[1, 2, 3, 4, 5, 6, 18, 24, 25, 66];

        let lines: Vec<&str> = PLAN.lines().collect();
        let heading = lines
            .iter()
            .position(|line| line.trim_end() == "## Review log")
            .expect("the plan has no Review log section");

        let mut rounds = 0;
        let mut unrecorded = Vec::new();
        for line in &lines[heading + 1..] {
            if line.starts_with("## ") || line.starts_with("### ") {
                break;
            }
            let Some(rest) = line.strip_prefix("| R") else {
                continue;
            };
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                // The header row starts the same way.
                continue;
            }
            let round: u32 = digits
                .parse()
                .unwrap_or_else(|_| panic!("a review log row has an unreadable round: {line}"));
            rounds += 1;
            let has_hash = line
                .match_indices('`')
                .filter_map(|(at, _)| line[at + 1..].split('`').next())
                .any(|inside| inside.len() == 7 && inside.chars().all(|c| c.is_ascii_hexdigit()));
            if !has_hash {
                unrecorded.push(round);
            }
        }
        assert!(rounds > 100, "the review log yielded only {rounds} rounds");
        unrecorded.sort_unstable();
        assert_eq!(
            unrecorded, UNRECORDED,
            "the rounds with no commit hash changed: a row either lost the hash that let a reader \
             follow it, or a round that can name its commit did not"
        );
    }

    /// No line of the plan claims a filter passed more tests than the filter now selects.
    ///
    /// The evidence rows record counts ("18 passed") so a later reviewer can tell whether the
    /// suite still covers what the row claims. A count that has since fallen is not an accounting
    /// detail: either a test was removed or renamed and the row kept its old number, and both
    /// mean the row is no longer evidence of anything. Counts may grow freely; they may not
    /// shrink. The revision history is exempt: it records what a count was at the time.
    #[test]
    fn the_plan_never_claims_more_tests_than_the_filter_selects() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let unit = test_names_in(
            &CRATE_SOURCES
                .iter()
                .filter(|(path, _)| path.starts_with("src/"))
                .copied()
                .collect::<Vec<_>>(),
        );
        let lines: Vec<&str> = PLAN.lines().collect();
        let history_start = lines
            .iter()
            .position(|line| line.trim_end() == "### 修订历史")
            .expect("the plan has no 修订历史 section");
        let history_end = lines[history_start + 1..]
            .iter()
            .position(|line| line.starts_with("## ") || line.starts_with("### "))
            .map_or(lines.len(), |offset| history_start + 1 + offset);

        let mut claims = 0;
        for line in lines[..history_start].iter().chain(&lines[history_end..]) {
            let starts: Vec<usize> = line
                .match_indices("cargo test --lib ")
                .map(|(at, _)| at)
                .collect();
            for (position, start) in starts.iter().enumerate() {
                let end = starts.get(position + 1).copied().unwrap_or(line.len());
                let segment = &line[start + "cargo test --lib ".len()..end];
                let filter: String = segment
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                if filter.is_empty() {
                    continue;
                }
                let Some(claim) = claimed_passes(segment) else {
                    continue;
                };
                let selected = unit.iter().filter(|name| name.contains(&filter)).count();
                claims += 1;
                assert!(
                    selected >= claim,
                    "the plan says `cargo test --lib {filter}` passed {claim} tests, but the filter \
                     now selects {selected}: a row that outlives its tests is not evidence"
                );
            }
        }
        assert!(
            claims >= 5,
            "only {claims} rows carry a test count: the scan is not reading the evidence rows"
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

        let unit = test_names_in(
            &CRATE_SOURCES
                .iter()
                .filter(|(path, _)| path.starts_with("src/"))
                .copied()
                .collect::<Vec<_>>(),
        );
        let integration = test_names_in(
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
                assert!(
                    names.iter().any(|name| name.contains(filter)),
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
