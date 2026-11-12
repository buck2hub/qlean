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

    /// The UTC date of the machine running the tests, as `YYYY-MM-DD`.
    ///
    /// Written out rather than pulled from a crate so the guard below needs no dependency: the
    /// count of days since the epoch converts to a civil date by the usual shift-and-divide.
    fn today_utc() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is before the epoch")
            .as_secs() as i64;
        let days = secs.div_euclid(86_400) + 719_468;
        let era = days.div_euclid(146_097);
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 {
            month_index + 3
        } else {
            month_index - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        format!("{year:04}-{month:02}-{day:02}")
    }

    /// The body of the function whose signature starts with `signature`, braces balanced.
    ///
    /// Every guard below that reasons about *where* code lives needs this: a check that a name
    /// is somewhere in a file cannot tell "the gate is in `Machine::new`" from "the gate is in
    /// some other function in the same file", and that difference is the whole point.
    fn body_of(source: &str, signature: &str) -> String {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} is gone: the guard would be reading nothing"));
        let mut depth = 0i32;
        let mut body = String::new();
        let mut seen = false;
        for ch in source[start..].chars() {
            match ch {
                '{' => {
                    depth += 1;
                    seen = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
            if seen {
                body.push(ch);
            }
            if seen && depth == 0 {
                break;
            }
        }
        body
    }

    /// Each card's id, lifecycle and acceptance token, in the order the plan declares them.
    fn card_states(plan: &str) -> Vec<(String, String, String)> {
        let mut cards: Vec<(String, String, String)> = Vec::new();
        let mut current: Option<String> = None;
        for line in plan.lines() {
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
        cards
    }

    /// How many acceptance criteria each card declares, keyed by card id.
    fn acceptance_counts(plan: &str) -> Vec<(String, usize)> {
        let mut counts: Vec<(String, usize)> = Vec::new();
        let mut current: Option<String> = None;
        let mut counting = false;
        for line in plan.lines() {
            if let Some(rest) = line.strip_prefix("### Task ") {
                current = Some(rest.split(':').next().unwrap_or(rest).trim().to_string());
                counting = false;
                continue;
            }
            if line.starts_with("## ") {
                current = None;
                counting = false;
                continue;
            }
            if line.starts_with("**Acceptance criteria:**") {
                counting = true;
                let id = current
                    .clone()
                    .unwrap_or_else(|| panic!("an acceptance block sits outside a card: {line}"));
                counts.push((id, 0));
                continue;
            }
            if line.starts_with("**") {
                counting = false;
                continue;
            }
            if counting
                && (line.starts_with("- [x] ") || line.starts_with("- [ ] "))
                && let Some((_, count)) = counts.last_mut()
            {
                *count += 1;
            }
        }
        counts
    }

    /// Every `- [x]`/`- [ ]` bullet in each card's `**Verification:**` block.
    fn verification_bullets(plan: &str) -> Vec<(String, String)> {
        let mut bullets: Vec<(String, String)> = Vec::new();
        let mut current: Option<String> = None;
        let mut reading = false;
        for line in plan.lines() {
            if let Some(rest) = line.strip_prefix("### Task ") {
                current = Some(rest.split(':').next().unwrap_or(rest).trim().to_string());
                reading = false;
                continue;
            }
            if line.starts_with("## ") {
                current = None;
                reading = false;
                continue;
            }
            if line.starts_with("**Verification:**") {
                reading = true;
                continue;
            }
            if line.starts_with("**") {
                reading = false;
                continue;
            }
            let bullet = line.starts_with("- [x] ") || line.starts_with("- [ ] ");
            if reading && bullet {
                let id = current
                    .clone()
                    .unwrap_or_else(|| panic!("a verification bullet sits outside a card: {line}"));
                bullets.push((id, line.to_string()));
            }
        }
        bullets
    }

    /// The body of the section whose heading line is exactly `heading`.
    ///
    /// Several headings are also quoted inside revision-history rows, so locating a section by
    /// substring finds the mention instead of the section - line-exact matching is the only way
    /// to be sure.
    fn section<'a>(text: &'a str, heading: &str) -> &'a str {
        let start = text
            .match_indices(heading)
            .find(|(at, _)| {
                let before_ok = *at == 0 || text[..*at].ends_with('\n');
                let after_ok = text[*at + heading.len()..].starts_with('\n');
                before_ok && after_ok
            })
            .map(|(at, _)| at)
            .unwrap_or_else(|| panic!("the plan has no `{heading}` heading of its own"));
        let after = &text[start + heading.len()..];
        let end = after
            .match_indices("\n## ")
            .next()
            .map(|(at, _)| at)
            .unwrap_or(after.len());
        &after[..end]
    }

    /// The lines of the plan's dependency registry.
    fn dependency_registry(plan: &str) -> Vec<&str> {
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

    /// The row of a markdown table whose first cell is `id`.
    fn table_row<'a>(text: &'a str, id: &str) -> Option<&'a str> {
        let prefix = format!("| {id} |");
        text.lines().find(|line| line.starts_with(&prefix))
    }

    /// The digits after `marker`, if the text states one.
    fn number_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
        let at = text.find(marker)?;
        let after = &text[at + marker.len()..];
        let digits: &str = after.split(|c: char| !c.is_ascii_digit()).next()?;
        (!digits.is_empty()).then_some(digits)
    }

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
    /// The status digest mentions every round the review log records.
    ///
    /// The status view opens with one long parenthetical listing what each round did, appended by
    /// hand after every round. The review log is the record; the digest is the summary a reader
    /// skims. If a round lands in the log and never in the digest, the summary silently stops
    /// being a summary of the document it summarises. Rounds 1-4 predate the first task card and
    /// are the one allowed exception; the exception is a whitelist of numbers, not a rule about
    /// position, so a round that skips the digest still fails.
    #[test]
    fn the_status_digest_covers_every_review_round() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");

        fn rounds(text: &str, pattern: &str) -> Vec<u32> {
            let mut found = Vec::new();
            let mut rest = text;
            while let Some(at) = rest.find(pattern) {
                rest = &rest[at + pattern.len()..];
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(number) = digits.parse() {
                    found.push(number);
                }
            }
            found
        }

        let log = section(PLAN, "## Review log");
        let logged: Vec<u32> = log
            .lines()
            .map(|line| rounds(line, "| R"))
            .filter_map(|found| found.first().copied())
            .collect();
        assert!(
            logged.windows(2).all(|pair| pair[0] > pair[1]),
            "the review log is no longer newest-first, so the numbers below cannot be trusted"
        );

        let digest = STATUS
            .lines()
            .find(|line| line.starts_with("| [`plan-20261104-windows-guest.md`]"))
            .expect("the status view no longer has a row for this plan");
        let summarised = rounds(digest, "R");

        const PREFACE_ROUNDS: [u32; 4] = [1, 2, 3, 4];
        for round in &logged {
            if PREFACE_ROUNDS.contains(round) {
                continue;
            }
            assert!(
                summarised.contains(round),
                "review round R{round} is in the log but the status digest never mentions it"
            );
        }
        for round in &summarised {
            assert!(
                logged.contains(round),
                "the status digest mentions R{round}, which no review round records"
            );
        }
    }

    /// The review log reads newest-first, with every round exactly once and none missing.
    ///
    /// The log grew in two directions: rounds 1-94 were appended oldest-first, then rounds 95+
    /// were prepended newest-first *below* them, so the table ran R1..R94 and then R124..R95. A
    /// reader looking for the latest review found it in the lower half, and nothing said which end
    /// was newer. The order is now newest-first throughout, matching the revision history, and this
    /// keeps it that way: strictly descending, contiguous, no round twice.
    #[test]
    fn the_review_log_reads_newest_first() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let logged: Vec<u32> = section(PLAN, "## Review log")
            .lines()
            .filter_map(|line| line.strip_prefix("| R"))
            .filter_map(|rest| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse().ok()
            })
            .collect();
        assert!(!logged.is_empty(), "the review log has no rows");

        for pair in logged.windows(2) {
            assert!(
                pair[0] > pair[1],
                "the review log runs R{} before R{}: newest-first means the larger number comes first",
                pair[0],
                pair[1]
            );
        }
        let newest = logged[0];
        assert_eq!(
            logged.len() as u32,
            newest,
            "the review log claims to end at R{newest} but holds {} rows, so a round is missing or doubled",
            logged.len()
        );
    }

    /// The plan names the CI jobs the workflow actually runs.
    ///
    /// DEP-03's success criterion is that four named jobs are green on the pushed commit. Those
    /// names are typed into two documents by hand while the workflow is edited elsewhere, so a
    /// renamed job - or a fifth one added - leaves the criterion describing a CI that no longer
    /// exists. Nobody can check the colour of the jobs from here; this checks that the names being
    /// watched are the names that run.
    #[test]
    fn the_plan_names_the_ci_jobs_the_workflow_runs() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const WORKFLOW: &str = include_str!("../.github/workflows/check-and-test.yml");

        let mut ran: Vec<&str> = WORKFLOW
            .lines()
            .filter_map(|line| line.strip_prefix("    name: "))
            .map(str::trim)
            .collect();
        ran.sort_unstable();
        assert_eq!(
            ran.len(),
            4,
            "the workflow runs {} jobs: {ran:?}",
            ran.len()
        );

        // Only the plan names the jobs; the status view refers to them by count.
        let registry = dependency_registry(PLAN).join("\n");
        let plan_row = table_row(&registry, "DEP-03").expect("the plan registry has no DEP-03 row");
        let at = plan_row
            .find("job（")
            .expect("the plan's DEP-03 row no longer lists the CI jobs");
        let after = &plan_row[at + "job（".len()..];
        let list = &after[..after.find('）').expect("the job list is unclosed")];
        let mut named: Vec<&str> = list.split(" / ").map(str::trim).collect();
        named.sort_unstable();
        assert_eq!(
            named, ran,
            "the plan watches {named:?} but the workflow runs {ran:?}"
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

        let plan_registry = dependency_registry(PLAN).join("\n");
        let policy_row =
            table_row(&plan_registry, "DEP-03").expect("the plan registry has no DEP-03 row");
        let status_row = table_row(STATUS, "DEP-03").expect("the status view has no DEP-03 row");

        let stated = [
            ("the plan", policy_row, "领先远端 "),
            ("the status view", status_row, "届时推送 "),
        ];
        let counts: Vec<(&str, &str)> = stated
            .iter()
            .map(|(who, row, marker)| {
                (
                    *who,
                    number_after(row, marker).unwrap_or_else(|| {
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
            first_stamp(policy_row),
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
                // Only a bare name counts. A string literal that merely starts with the prefix -
                // prose handed to a user, a message quoted from a test - is not an override, and
                // counting it turned the failure message into nonsense.
                let name = &after[..end];
                let shaped = name.strip_prefix("QLEAN_").is_some_and(|tail| {
                    !tail.is_empty()
                        && tail
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                });
                if shaped {
                    read.push(name);
                }
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

        let cards = card_states(PLAN);
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

    /// The evidence summary counts the acceptance criteria its card actually declares.
    ///
    /// The evidence row records the review as "逐条核对 N 条 AC". N is a hand-typed count of
    /// bullets that live in a different part of the same document, and it is the number a reader
    /// uses to decide whether the review covered everything. The template also caps a card at
    /// eight criteria, so a ninth bullet would be a rule violation rather than a detail.
    #[test]
    fn the_evidence_summary_counts_the_acceptance_criteria_each_card_declares() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let counts = acceptance_counts(PLAN);
        assert_eq!(counts.len(), 10, "the plan declares {} cards", counts.len());

        for (id, declared) in &counts {
            assert!(
                (1..=8).contains(declared),
                "card {id} declares {declared} acceptance criteria; the template caps a card at 8"
            );
            let prefix = format!("| {id} | 20");
            let row = PLAN
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("the evidence summary has no row for {id}"));
            let Some(at) = row.find("条 AC") else {
                continue;
            };
            let claimed: String = row[..at]
                .trim_end()
                .chars()
                .rev()
                .take_while(char::is_ascii_digit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            assert_eq!(
                claimed.parse::<usize>().ok(),
                Some(*declared),
                "card {id} declares {declared} acceptance criteria but its evidence row claims {claimed}"
            );
        }
    }

    /// The seven ignored Windows smoke tests all stop at the precondition the plan describes.
    ///
    /// Every Windows smoke test reaches the host gate, because it builds its machine through it.
    ///
    /// The seven ignored tests are the only evidence that will ever exist for a real Windows
    /// boot, and the gate that stops them on an unprepared host lives inside `Machine::new`.
    /// A test that started QEMU some other way would still be called "the Windows smoke test"
    /// while skipping the one check that says whether the host can run it at all.
    #[test]
    fn the_windows_smoke_tests_all_go_through_the_prerequisite_gate() {
        let suite = CRATE_SOURCES
            .iter()
            .find(|(path, _)| *path == "tests/windows_machine.rs")
            .map(|(_, source)| *source)
            .expect("the Windows suite is not in CRATE_SOURCES");

        let mut tested = 0;
        for (index, line) in suite.lines().enumerate() {
            let trimmed = line.trim_start();
            let Some(name) = trimmed.strip_prefix("async fn windows_") else {
                continue;
            };
            if name.starts_with("image_config") {
                continue;
            }
            let name = format!("windows_{}", name.trim_end_matches("() -> Result<()> {"));
            let body: String = suite
                .lines()
                .skip(index + 1)
                .scan(1i32, |depth, line| {
                    *depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
                    Some((*depth, line))
                })
                .take_while(|(depth, _)| *depth > 0)
                .map(|(_, line)| line)
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                body.contains("Machine::new") || body.contains("MachinePool::new"),
                "{name} builds its machine without Machine::new or MachinePool::new, so it never \
                 passes firmware::ensure_host_support"
            );
            tested += 1;
        }
        assert_eq!(tested, 7, "the suite should hold seven Windows smoke tests");

        let machine = body_of(
            CRATE_SOURCES
                .iter()
                .find(|(path, _)| *path == "src/machine.rs")
                .map(|(_, source)| *source)
                .expect("src/machine.rs is not in CRATE_SOURCES"),
            "pub async fn new(image: &Image, config: &MachineConfig)",
        );
        assert!(
            machine.contains("firmware::ensure_host_support()?"),
            "Machine::new no longer gates a Windows guest on firmware::ensure_host_support"
        );
        let pool = body_of(
            CRATE_SOURCES
                .iter()
                .find(|(path, _)| *path == "src/pool.rs")
                .map(|(_, source)| *source)
                .expect("src/pool.rs is not in CRATE_SOURCES"),
            "pub async fn add(",
        );
        assert!(
            pool.contains("Machine::new(image, config)"),
            "MachinePool::add no longer builds its machines through Machine::new"
        );
    }

    /// The cells of a Markdown table row, honoring escaped pipes.
    fn table_cells(line: &str) -> Vec<String> {
        let mut cells = Vec::new();
        let mut current = String::new();
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => match chars.peek() {
                    Some('|') => {
                        current.push('|');
                        chars.next();
                    }
                    _ => current.push(ch),
                },
                '|' => {
                    cells.push(current.trim().to_string());
                    current.clear();
                }
                _ => current.push(ch),
            }
        }
        // A row starts with a delimiter, so the first cell is the empty prefix; every cell
        // after it is pushed when its closing delimiter is met.
        if !cells.is_empty() {
            cells.remove(0);
        }
        cells
    }

    /// The body of the function whose signature starts at `signature`, brace-matched.
    fn function_body(source: &'static str, signature: &str) -> &'static str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("`{signature}` must still exist"));
        let mut depth = 0usize;
        let mut started = false;
        let mut end = source.len();
        for (offset, ch) in source[start..].char_indices() {
            match ch {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => {
                    depth -= 1;
                    if started && depth == 0 {
                        end = start + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        &source[start..end]
    }

    /// A tree walk that cannot read an entry fails instead of skipping it.
    ///
    /// `walk_remote_dir` backs `Machine::download` and `remove_dir_all`. It used to log a
    /// failed `read_dir`/`metadata` at debug level and `continue`, so downloading a tree
    /// that held a broken symlink (stat follows the link and fails) or an unreadable
    /// directory returned `Ok` with those entries missing - the copy was silently
    /// incomplete while the README promised that a link is never silently skipped. The
    /// guard reads the function body and requires the two failures to be reported with the
    /// path, and rejects the debug-and-continue shape coming back.
    #[test]
    fn the_remote_walk_reports_entries_it_cannot_read() {
        let body = function_body(
            include_str!("ssh.rs"),
            "pub(crate) async fn walk_remote_dir(",
        );

        assert!(
            !body.contains("debug!"),
            "a skipped entry makes the copy silently incomplete; report it instead"
        );
        for phrase in [
            "Failed to read the remote directory",
            "Failed to stat",
            "while walking",
        ] {
            assert!(
                body.contains(phrase),
                "the walk must name what it could not read: `{phrase}` is gone"
            );
        }
        assert!(
            !body.contains("best-effort"),
            "best-effort traversal is exactly what the documented contract forbids"
        );
    }

    /// Both tables in the plan have the number of columns their own header declares.
    ///
    /// The `## Review log` header has six columns and `### 修订历史` has five, but 42 review
    /// rows had lost the `P2 处置` cell (the evidence text slid one column left) and one had
    /// gained an extra cell, while nine history rows carried unescaped `|` inside code spans
    /// (`| <卡号> |`, `chars().map(|c| c as u16)`, `| Round |`) that split the row into
    /// phantom cells when rendered. Nothing checked either table, so the drift survived 140
    /// rounds. A row now has to match its header, the review log's `P2 处置` cell has to say
    /// something, and rows that render short or long are named by round.
    #[test]
    fn every_table_row_has_the_columns_its_header_declares() {
        let plan = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        for (heading, columns, row_prefix, marker) in [
            ("## Review log", 6usize, "| R", "| PASS"),
            ("### 修订历史", 5usize, "| 20", " UTC | "),
        ] {
            // Match the heading as a whole line: the same text appears inside a history row.
            let at = plan
                .lines()
                .position(|line| line.trim_end() == heading)
                .unwrap_or_else(|| panic!("`{heading}` must still exist as its own line"));
            let mut lines = plan
                .lines()
                .skip(at + 1)
                // Skip the prose between the heading and its table.
                .skip_while(|line| !line.starts_with('|'));
            let header = lines.next().unwrap_or_default();
            assert_eq!(
                table_cells(header).len(),
                columns,
                "`{heading}`: the header is not the width the test knows ({} cells): {header}",
                table_cells(header).len()
            );
            let mut checked = 0usize;
            let mut offenders = Vec::new();
            for line in lines {
                if line.starts_with('#') {
                    break;
                }
                if !line.starts_with(row_prefix) || line.starts_with("|---") {
                    continue;
                }
                checked += 1;
                let cells = table_cells(line);
                let label: String = line.chars().take(12).collect();
                if cells.len() != columns {
                    offenders.push(format!("{label} has {} cells", cells.len()));
                } else if columns == 6 && cells[4].is_empty() {
                    offenders.push(format!("{label} leaves `P2 处置` empty"));
                }
            }
            assert!(
                offenders.is_empty(),
                "`{heading}` rows do not match the {columns}-column header: {offenders:?}"
            );
            assert!(
                checked >= 100,
                "`{heading}`: only {checked} rows scanned, the section heading or row shape moved"
            );
            // A row that loses its leading `|` stops looking like a row at all, so count the
            // mark every row of this table carries and hold it against the rows surveyed.
            let marked = plan
                .lines()
                .skip(at + 1)
                .take_while(|line| !line.starts_with('#'))
                // The result cell is `PASS` or `FAIL`, sometimes with a qualifier.
                .filter(|line| line.contains(marker) || line.contains("| FAIL"))
                .count();
            assert_eq!(
                marked, checked,
                "`{heading}`: {marked} lines carry the row mark but {checked} rows were \
                 surveyed — a row lost its leading `|`"
            );
        }
    }

    /// The walk classifies each entry as itself, not as whatever it points at.
    ///
    /// `walk_remote_dir` used `metadata` (SSH_FXP_STAT), which follows links. Measured
    /// against OpenSSH's own `sftp-server`: STAT on a link to a directory answers with the
    /// directory's mode, and STAT on a broken link answers `NO_SUCH_FILE` while LSTAT
    /// answers `0120777`. A walk built on STAT therefore cannot see links at all - so a
    /// downloaded tree silently folded a linked directory's contents into the copy instead
    /// of failing on the link, and a tree holding a broken link could not even be collected
    /// (R142) or removed, although removing the link is a single request.
    #[test]
    fn the_remote_walk_stats_the_entry_not_its_target() {
        let body = function_body(
            include_str!("ssh.rs"),
            "pub(crate) async fn walk_remote_dir(",
        );

        // Two calls: the root and each visited child. The single following stat left in the
        // function is the `follow_links` branch, which dereferences on purpose.
        assert_eq!(
            body.matches("symlink_metadata").count(),
            2,
            "the walk must ask for the entry's own attributes for the root and for each child"
        );
        assert_eq!(
            body.matches("sftp.metadata(").count(),
            1,
            "a following stat hides links and cannot answer for a broken one outside `follow_links`"
        );
    }

    /// The `source`/`digest` docs state the rule the code enforces, not a softer one.
    ///
    /// `ImageConfig::validate` refuses a half-set pair outright - an image is never fetched
    /// without a digest to verify it against - but both fields documented the digest as
    /// something that "should be provided along with the source", which reads as advice. A
    /// reader who follows the advice gets a hard error far from the sentence, and one who
    /// omits both learns nothing from the field docs. The guard reads the doc comments that
    /// sit directly above the two fields (and their README copy) so prose elsewhere in the
    /// file cannot satisfy it.
    #[test]
    fn the_image_config_fields_document_the_digest_rule_the_code_enforces() {
        fn doc_above(file: &str, field: &str) -> String {
            let lines: Vec<&str> = file.lines().collect();
            let at = lines
                .iter()
                .position(|line| line.trim() == field)
                .unwrap_or_else(|| panic!("`{field}` must still be a field on its own line"));
            let mut doc = Vec::new();
            for line in lines[..at].iter().rev() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("///") {
                    doc.push(rest.trim().to_string());
                } else {
                    break;
                }
            }
            assert!(
                !doc.is_empty(),
                "`{field}` must keep a doc comment: it carries the rule the code enforces"
            );
            doc.reverse();
            doc.join(" ")
        }

        for (name, text) in [
            ("src/image.rs", include_str!("image.rs")),
            ("README.md", include_str!("../README.md")),
        ] {
            for field in ["pub source: Option<String>,", "pub digest: Option<String>,"] {
                let doc = doc_above(text, field);
                assert!(
                    doc.contains("must both be set or both omitted")
                        || doc.contains("must be set together with `source`"),
                    "{name}: the doc above `{field}` must state the rule: {doc}"
                );
                assert!(
                    !doc.contains("should"),
                    "{name}: the doc above `{field}` hedges a rule the code enforces: {doc}"
                );
            }
        }
    }

    /// The image contract requires PowerShell, because `exec` sends the command verbatim.
    ///
    /// `exec` hands the user's string straight to the guest's default shell with no wrapping,
    /// so the documented PowerShell example only works when the image changed OpenSSH's
    /// `DefaultShell`. Qlean's own probes dodge that requirement by encoding themselves; a
    /// user's `exec` cannot. A contract sentence that hedges ("should set") reads as optional
    /// and leaves the documented example failing under a stock `cmd.exe` default shell, so the
    /// requirement is pinned as a must and the hedge is rejected outright.
    #[test]
    fn the_image_contract_requires_powershell_as_the_default_shell() {
        let readme = include_str!("../README.md");
        let contract = readme
            .split("#### Windows image contract")
            .nth(1)
            .and_then(|rest| rest.split("#### Windows transport and security").next())
            .expect("the README must keep the Windows image contract in its own section");

        // Re-wrapping the paragraph must not decide whether the requirement still holds.
        let flat = contract.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("must set the OpenSSH default shell to PowerShell"),
            "the contract must state that the image sets OpenSSH's DefaultShell to PowerShell"
        );
        // Whole phrases only: `contains("DefaultShell")` would also accept a renamed value
        // such as `DefaultShellValue`, which no image would ever read.
        let binary = "`HKLM:\\SOFTWARE\\OpenSSH` -> `DefaultShell` = \
                      `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`";
        assert!(
            flat.contains(binary),
            "the contract must name the registry value and the shell an image has to set: {binary}"
        );
        assert!(
            !flat.contains("should set"),
            "an image requirement written as `should` reads as optional, and `exec` would then \
             run PowerShell syntax under cmd.exe"
        );
    }

    /// The library test count the evidence rows claim only ever grows.
    ///
    /// Every round records `cargo test --lib` in its revision-history row. Those numbers are
    /// copied by hand, and one round quoting an older count reads as a round that *removed*
    /// tests - the one direction the plan says never happens. The final count is also what a
    /// reader compares against their own run, so it has to be the newest round's number.
    #[test]
    fn the_library_test_counts_in_the_evidence_only_grow() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let mut claims: Vec<(u32, u32)> = Vec::new();
        for line in PLAN.lines() {
            if !line.starts_with("| 2026-") {
                continue;
            }
            let Some(at) = line.find("review R") else {
                continue;
            };
            let round: u32 = line[at + "review R".len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .expect("a revision-history row names its round in digits");
            // The last count in the row is the round's closing number.
            let mut claimed = None;
            let mut rest = line;
            while let Some(hit) = rest.find(" passed / ") {
                let digits: String = rest[..hit]
                    .chars()
                    .rev()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                let tail = &rest[hit + " passed / ".len()..];
                let ignored: String = tail
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>();
                // Only the documented "N passed / M ignored" shape is a claim about the suite.
                if !ignored.is_empty()
                    && tail[ignored.len()..].starts_with(" ignored")
                    && let Ok(value) = digits.parse::<u32>()
                {
                    claimed = Some(value);
                }
                rest = tail;
            }
            if let Some(value) = claimed {
                claims.push((round, value));
            }
        }
        claims.sort_unstable();
        assert!(
            claims.len() >= 30,
            "only {} rows quote a test count: the scan is not reading them",
            claims.len()
        );
        for pair in claims.windows(2) {
            let ((before, smaller), (after, larger)) = (pair[0], pair[1]);
            assert!(
                larger >= smaller,
                "round R{after} claims {larger} passing tests but the older R{before} already \
                 claimed {smaller}: a round cannot shrink the suite"
            );
        }
    }

    /// No document dates an observation later than the clock, not just the plan.
    ///
    /// The plan's dates are checked; the status view was not, and it carried seven timestamps two
    /// days ahead - six card rows and one deferred item whose "last updated" moment had not
    /// arrived. A note at the top of the file declared them estimates, which is honest about the
    /// problem and still leaves a reader who opens one row with a date that means nothing.
    #[test]
    fn the_status_view_states_no_date_that_has_not_happened_yet() {
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");
        let today = today_utc();
        let mut checked = 0;
        for line in STATUS.lines() {
            // The note that explains the old estimates quotes the dates it is talking about, and a
            // quoted date is a mention rather than a claim. Everything else in it is a claim.
            let note: String;
            let line = if line.trim_start().starts_with('>') {
                note = line
                    .split('`')
                    .enumerate()
                    .filter(|(index, _)| index % 2 == 0)
                    .map(|(_, text)| text)
                    .collect();
                note.as_str()
            } else {
                line
            };
            let bytes = line.as_bytes();
            for at in 0..bytes.len().saturating_sub(9) {
                let window = &bytes[at..at + 10];
                let shaped = window[..4].iter().all(u8::is_ascii_digit)
                    && window[4] == b'-'
                    && window[5..7].iter().all(u8::is_ascii_digit)
                    && window[7] == b'-'
                    && window[8..10].iter().all(u8::is_ascii_digit);
                if !shaped {
                    continue;
                }
                let date = std::str::from_utf8(window).expect("a date is not ascii");
                checked += 1;
                assert!(
                    date <= today.as_str(),
                    "the status view records {date}, but the clock says {today}: that row claims \
                     an update that has not happened"
                );
            }
        }
        assert!(
            checked >= 10,
            "the status view yielded only {checked} dates: the scan is not looking at them"
        );
    }

    /// Every dependency the documents cite has a row, in the registry that defines it.
    ///
    /// `DEFER-05` was cited by the plan and registered in the status view but never entered the
    /// plan's own deferred table, so the instruction "registered as DEFER-05" pointed at nothing
    /// in the document it named.
    #[test]
    fn every_deferral_the_documents_cite_is_registered_in_the_plan() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");

        let section_start = PLAN
            .lines()
            .position(|line| line.trim_end() == "## 非目标与延后项")
            .expect("the plan has no deferred-items section");
        let rows: Vec<String> = PLAN
            .lines()
            .skip(section_start + 1)
            .take_while(|line| !line.starts_with("## "))
            .filter_map(|line| line.split('|').nth(1).map(|id| id.trim().to_owned()))
            .filter(|id| id.starts_with("DEFER-"))
            .collect();
        assert!(
            rows.len() >= 4,
            "the deferred table lists {} rows: the parse is not reading it",
            rows.len()
        );

        let mut cited = 0;
        for (who, document) in [("the plan", PLAN), ("the status view", STATUS)] {
            for word in document.split(|c: char| !c.is_alphanumeric() && c != '-') {
                let Some(id) = word.strip_prefix("DEFER-") else {
                    continue;
                };
                if id.len() != 2 || !id.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                cited += 1;
                assert!(
                    rows.iter().any(|row| row == word),
                    "{who} cites {word}, but the plan's deferred table has no row for it"
                );
            }
        }
        assert!(cited >= 8, "only {cited} deferrals were cited anywhere");
    }

    /// Every `src/file.rs::symbol` the plan points at names something that is there.
    ///
    /// The write-set rows exist so a reader can go and look at the implementation. Three of them
    /// named functions that no commit in this repository ever contained, which is worse than a
    /// stale name: the reader cannot tell "renamed" from "never existed" and has nothing to
    /// search for. The revision history is exempt because it quotes the past on purpose.
    #[test]
    fn the_plan_points_only_at_symbols_the_named_files_contain() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let mut checked = 0;
        let mut in_history = false;
        for line in PLAN.lines() {
            let trimmed = line.trim_end();
            if trimmed.starts_with("## ") || trimmed.starts_with("### ") {
                in_history = trimmed == "### 修订历史";
            }
            if in_history {
                continue;
            }
            let mut rest = line;
            while let Some(at) = rest.find("src/") {
                rest = &rest[at..];
                let Some(colon) = rest.find("::") else {
                    rest = &rest[1..];
                    continue;
                };
                let path = &rest[..colon];
                if !path.ends_with(".rs") || path.contains(' ') {
                    rest = &rest[1..];
                    continue;
                }
                let after = &rest[colon + 2..];
                let symbol: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                rest = &rest[colon + 2..];
                if symbol.is_empty() {
                    continue;
                }
                let leaf = symbol.split("::").next().expect("a split has one part");
                let source = CRATE_SOURCES
                    .iter()
                    .find(|(crate_path, _)| *crate_path == path)
                    .map(|(_, source)| *source)
                    .unwrap_or_else(|| panic!("the plan names {path}, which is not a crate file"));
                checked += 1;
                assert!(
                    source.contains(leaf),
                    "the plan points at {path}::{symbol}, but {path} does not contain {leaf}: \
                     either the name is stale or it never existed"
                );
            }
        }
        assert!(
            checked >= 30,
            "the plan yielded only {checked} symbol citations: the scan is not looking at them"
        );
    }

    /// The number of ignored unit tests the plan runs is the number the crate has.
    ///
    /// The test matrix says the container snapshot runs "all 11" of them; a twelfth `#[ignore]`
    /// would quietly leave the snapshot looking complete while covering less, and nobody would
    /// see it because the count and the code are two places that never compared.
    #[test]
    fn the_plan_runs_the_ignored_unit_tests_it_counts() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let ignored: usize = CRATE_SOURCES
            .iter()
            .filter(|(path, _)| path.starts_with("src/"))
            .map(|(_, source)| {
                source
                    .lines()
                    .filter(|line| line.trim_start().starts_with("#[ignore"))
                    .count()
            })
            .sum();
        assert!(
            ignored >= 5,
            "the crate has only {ignored} ignored tests: the scan is not reading the sources"
        );

        let row = PLAN
            .lines()
            .find(|line| line.starts_with("| 真程序证据全量快照 |"))
            .expect("the test matrix has no container snapshot row");
        let stated = row
            .split("跑全部 ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|word| word.strip_suffix('条').or(Some(word)))
            .and_then(|word| word.parse::<usize>().ok())
            .unwrap_or_else(|| {
                panic!("the snapshot row does not say how many tests it runs: {row}")
            });
        assert_eq!(
            stated, ignored,
            "the plan says the snapshot runs {stated} ignored tests, the crate has {ignored}"
        );
    }

    /// The plan quotes the prerequisite error the Windows gate prints, word for word.
    ///
    /// The plan tells a reader what happens once the image variables are set: the gate hands
    /// over to the host check, which names the missing program. A quote that drifts from the
    /// code sends someone looking for a message that no longer exists - and the ladder's last
    /// step is the one nobody can reach on this host, so the quote is all the reader has.
    #[test]
    fn the_plan_quotes_the_prerequisite_error_the_windows_gate_prints() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const FIRMWARE: &str = include_str!("../src/firmware.rs");
        const PROBE: &str = "was not found: a Windows guest's address comes from";

        assert_eq!(
            FIRMWARE.matches(PROBE).count(),
            1,
            "the lease-tool prerequisite message is not stated exactly once in firmware.rs"
        );
        // The template spans a continuation line, so the source text is unescaped and re-wrapped
        // before it is compared with the plan, which wraps nothing.
        let at = FIRMWARE.find(PROBE).expect("the probe is right above");
        let start = FIRMWARE[..at]
            .rfind("format!(")
            .expect("the message is not built by format!");
        let end = at
            + FIRMWARE[at..]
                .find("))")
                .expect("the message is not closed");
        let template = &FIRMWARE[start..end];
        let quoted = &template[template.find('"').expect("no quote") + 1
            ..template.rfind('"').expect("no closing quote")];
        let rendered = quoted
            .replace("\\\n", " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("{LEASE_TOOL}", "virsh");
        let flat = PLAN.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains(&rendered),
            "the plan does not quote the prerequisite error the gate prints; the gate says \
             {rendered}"
        );
        assert!(
            rendered.contains("virsh net-dhcp-leases"),
            "the lease tool is no longer looked up through net-dhcp-leases"
        );
    }

    /// No date in the plan lies in the future.
    ///
    /// R111 found a third of the revision history stamped with times that had not happened yet,
    /// and the same habit had leaked into two evidence rows and one sampling note - a reader
    /// cannot tell an invented date from a recorded one, so a plan that dates its evidence in the
    /// future dates all of it in doubt. The revision history is exempt because its bad rows are
    /// preserved on purpose and registered as unrecoverable; so is any line that says as much.
    #[test]
    fn the_plan_states_no_date_that_has_not_happened_yet() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let today = today_utc();
        let mut checked = 0;
        let mut in_history = false;
        for line in PLAN.lines() {
            let trimmed = line.trim_end();
            if trimmed.starts_with("## ") || trimmed.starts_with("### ") {
                in_history = trimmed == "### 修订历史";
            }
            if in_history || line.contains("不可回溯") {
                continue;
            }
            let bytes = line.as_bytes();
            for at in 0..bytes.len().saturating_sub(9) {
                let window = &bytes[at..at + 10];
                let shaped = window[..4].iter().all(u8::is_ascii_digit)
                    && window[4] == b'-'
                    && window[5..7].iter().all(u8::is_ascii_digit)
                    && window[7] == b'-'
                    && window[8..10].iter().all(u8::is_ascii_digit);
                if !shaped {
                    continue;
                }
                let date = std::str::from_utf8(window).expect("a date is not ascii");
                checked += 1;
                assert!(
                    date <= today.as_str(),
                    "the plan dates evidence {date}, but the clock says {today}: nothing can \
                     have been observed on that day yet"
                );
            }
        }
        assert!(
            checked >= 5,
            "the plan yielded only {checked} dates outside the revision history: the scan is not \
             looking at them"
        );
    }

    /// The plan says every ignored Windows test halts on the DEP-01 message, and that is only true
    /// while each of them goes through the shared `windows_image_config()` gate before touching a
    /// disk or a hypervisor. A new ignored test that reads the environment itself would make the
    /// sentence false without anything noticing - and the sentence is what a reader relies on to
    /// know these tests cost nothing on a host without a licensed image.
    #[test]
    fn the_windows_smoke_tests_all_gate_on_the_documented_precondition() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const SUITE: &str = include_str!("../tests/windows_machine.rs");
        // The fragment both sides must agree on; the suite adds "to run this test" after it.
        const FRAGMENT: &str = "must point at a licensed Windows qcow2 (DEP-01)";

        assert_eq!(
            SUITE.matches(FRAGMENT).count(),
            1,
            "the DEP-01 message is not stated exactly once in the suite"
        );
        assert!(
            PLAN.contains(FRAGMENT),
            "the plan does not quote the message the suite prints"
        );

        let mut checked = 0_usize;
        for block in SUITE.split("#[tokio::test]").skip(1) {
            if !block.contains("#[ignore") {
                continue;
            }
            let name = block
                .lines()
                .find_map(|line| line.trim().strip_prefix("async fn "))
                .and_then(|rest| rest.split('(').next())
                .unwrap_or_else(|| panic!("an ignored test has no name: {block}"));
            assert!(
                block.contains("windows_image_config()?"),
                "ignored test {name} does not gate on windows_image_config()"
            );
            checked += 1;
        }
        assert_eq!(
            checked, 7,
            "the suite has {checked} ignored Windows tests, the plan says 7"
        );
        assert!(
            PLAN.contains(&format!("{checked} 个 `#[ignore]` 用例")),
            "the plan does not state that {checked} tests are ignored"
        );
    }

    /// A card past the local gate records the documentation gate the plan requires of every card.
    ///
    /// The per-card gate names five commands, and one of them is
    /// `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`. That gate has bitten before - a public
    /// doc comment linking a private type fails it - yet no card recorded running it, so the one
    /// required command with a failure history was the one with no evidence in the document.
    #[test]
    fn the_done_cards_record_the_documentation_gate_the_plan_requires() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const GATE: &str = "RUSTDOCFLAGS=\"-D warnings\" cargo doc --no-deps";

        // A card with an acceptance value is a card that has been through the local gate, whatever
        // its lifecycle says about the Windows-hosted criteria still waiting on DEP-01/02.
        let accepted: Vec<String> = card_states(PLAN)
            .into_iter()
            .filter(|(_, _, acceptance)| acceptance != "空")
            .map(|(id, _, _)| id)
            .collect();
        assert_eq!(
            accepted.len(),
            7,
            "the plan declares {} cards past the local gate",
            accepted.len()
        );

        let bullets = verification_bullets(PLAN);
        for id in &accepted {
            let lines: Vec<&str> = bullets
                .iter()
                .filter(|(card, _)| card == id)
                .map(|(_, line)| line.as_str())
                .collect();
            assert!(!lines.is_empty(), "card {id} records no verification");
            assert!(
                lines.iter().any(|line| line.contains(GATE)),
                "card {id} is past the local gate but records no {GATE} result"
            );
        }
    }

    /// Every line citation in the plan points inside the file it names.
    ///
    /// The traceability table pins each card's evidence to a slice of source, like
    /// `src/machine.rs:578-775`. Those numbers are hand-typed and are never re-derived when the
    /// file grows or shrinks, so the one thing worth asserting is the cheap invariant: the file
    /// exists, the range starts at or after line 1, ends at or before the last line, and does not
    /// run backwards. A citation past the end of the file is not a matter of taste.
    #[test]
    fn the_plan_cites_line_ranges_inside_the_files_it_names() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let lengths: Vec<(&str, usize)> = CRATE_SOURCES
            .iter()
            .filter(|(path, _)| path.starts_with("src/"))
            .map(|(path, text)| (*path, text.lines().count()))
            .collect();
        assert_eq!(
            lengths.len(),
            12,
            "the crate has {} source files",
            lengths.len()
        );

        let mut seen = 0_usize;
        let mut rest = PLAN;
        while let Some(at) = rest.find("`src/") {
            rest = &rest[at + 1..];
            let Some(close) = rest.find('`') else { break };
            let citation = &rest[..close];
            let Some((path, spec)) = citation.split_once(':') else {
                continue;
            };
            if spec.is_empty()
                || !spec
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
            {
                continue;
            }
            let last = lengths
                .iter()
                .find(|(name, _)| *name == path)
                .map(|(_, last)| last)
                .unwrap_or_else(|| panic!("the plan cites {path}, which is not a source file"));
            for part in spec.split(',') {
                let (start, end) = match part.split_once('-') {
                    Some((start, end)) => (start, end),
                    None => (part, part),
                };
                let start: usize = start.parse().expect("a citation starts with a line number");
                let end: usize = end.parse().expect("a citation ends with a line number");
                assert!(
                    start >= 1 && start <= end,
                    "the plan cites {path}:{spec}, which is not a forward range"
                );
                assert!(
                    end <= *last,
                    "the plan cites {path}:{spec} but that file has {last} lines"
                );
                seen += 1;
            }
        }
        assert!(seen >= 40, "only {seen} line citations were checked");
    }

    /// The evidence summary repeats the lifecycle its card declares, in a third place.
    ///
    /// The same two tokens are written three times: in the card, in the status view's table and in
    /// the evidence summary that records how far the card actually got. The third copy is the one
    /// a reader consults when asking "is this card done", and it was the only one nothing checked -
    /// so a card could be `in-progress` everywhere else while the evidence table called it done.
    #[test]
    fn the_evidence_summary_repeats_the_lifecycle_each_card_declares() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let cards = card_states(PLAN);
        assert_eq!(cards.len(), 10, "the plan declares {} cards", cards.len());

        // `空` is how the tables spell an absent acceptance value.
        let plain = |token: &str| match token.trim().trim_matches('`') {
            "空" => String::new(),
            other => other.to_string(),
        };

        for (id, lifecycle, acceptance) in &cards {
            let prefix = format!("| {id} | 20");
            let row = PLAN
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("the evidence summary has no row for {id}"));
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            assert!(
                cells.len() > 5,
                "the evidence row for {id} lost its columns: {row}"
            );
            let (lifecycle_there, acceptance_there) = cells[5]
                .split_once('/')
                .unwrap_or_else(|| panic!("the evidence row for {id} states no pair: {row}"));
            assert_eq!(
                (plain(lifecycle_there), plain(acceptance_there)),
                (plain(lifecycle), plain(acceptance)),
                "card {id} declares {lifecycle} / {acceptance} but the evidence summary says {} / {}",
                plain(lifecycle_there),
                plain(acceptance_there)
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
                // `--test-threads 1` (without the `=`) hands the next token to a flag, not to
                // the filter; reading `1` as a filter turned a correct command into a failure.
                let mut skip_value = false;
                let filter = command.split_whitespace().skip(2).find(|token| {
                    if std::mem::take(&mut skip_value) {
                        return false;
                    }
                    if *token == "--test-threads" {
                        skip_value = true;
                        return false;
                    }
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
