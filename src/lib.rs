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

    /// Byte offset of the heading line that starts with `heading`.
    ///
    /// Prose may *mention* a heading - the revision history quotes card names when it
    /// describes a change to them - so a plain `find` can slice between two mentions inside
    /// one paragraph and assert nothing. Offsets taken here only ever point at a real heading
    /// line, which is what a guard that slices a card needs.
    fn heading_offset(text: &str, heading: &str) -> usize {
        text.match_indices(heading)
            .find(|(at, _)| *at == 0 || text[..*at].ends_with('\n'))
            .map(|(at, _)| at)
            .unwrap_or_else(|| panic!("the plan has no `{heading}` heading of its own"))
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

    /// The bullets of every `### <heading>` section inside the changelog's `[Unreleased]` block.
    ///
    /// Returned in document order as `(heading, bullets)`. A wrapped entry is flattened onto one
    /// line, because the sentence - not the line - is what gets classified: `... was parsed as`
    /// can straddle a wrap and a line-only reader would then see nothing wrong.
    fn changelog_sections(unreleased: &str) -> Vec<(String, Vec<String>)> {
        let mut sections: Vec<(String, Vec<String>)> = Vec::new();
        for line in unreleased.lines() {
            if let Some(heading) = line.strip_prefix("### ") {
                sections.push((heading.trim().to_string(), Vec::new()));
                continue;
            }
            let Some((_, bullets)) = sections.last_mut() else {
                continue;
            };
            if let Some(bullet) = line.strip_prefix("- ") {
                bullets.push(bullet.trim().to_string());
            } else if line.starts_with(' ')
                && !line.trim().is_empty()
                && let Some(last) = bullets.last_mut()
            {
                last.push(' ');
                last.push_str(line.trim());
            }
        }
        sections
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

    /// The marker a revision history row carries when nobody wrote its moment down.
    ///
    /// Fifty-three rows were dated two days ahead of the clock instead (F170): the ladder in the
    /// first column was reconstructed from round order, not observed, and the section was exempt
    /// from the no-future-dates guard, so nothing ever compared it to a clock.
    const HISTORY_UNRECORDED: &str = "不可回溯";

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
        let mut timestamped = 0usize;
        let mut unrecorded = 0usize;
        let mut unrecorded_blocks = 0usize;
        let mut previous_was_unrecorded = false;
        for row in body {
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            let (time, trigger) = (cells[1], cells[2]);
            // A row whose moment cannot be reconstructed says so; inventing a timestamp for it
            // is how fifty-three rows came to be dated after the clock (F170).
            let marker = time == HISTORY_UNRECORDED;
            assert!(
                marker || (time.len() == 23 && time.ends_with(" UTC")),
                "a revision history row has neither a `YYYY-MM-DD HH:MM:SS UTC` timestamp nor the \
                 `{HISTORY_UNRECORDED}` marker: {row}"
            );
            if marker {
                if !previous_was_unrecorded {
                    unrecorded_blocks += 1;
                }
                unrecorded += 1;
            } else {
                timestamped += 1;
            }
            previous_was_unrecorded = marker;
            let parsed = trigger.strip_prefix("review R").and_then(|rest| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<u32>().ok()
            });
            // A shifted column is the failure this catches: when the first cell of fifty-three rows
            // was replaced, one leftover time fragment stayed in the trigger column, `strip_prefix`
            // returned `None`, and the ordering check skipped those rows in silence (F170).
            assert!(
                parsed.is_some() || trigger == "成稿",
                "a revision history row does not name its round in the trigger cell, so its \
                 position is unchecked: {row}"
            );
            if let Some(number) = parsed {
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
        assert!(
            timestamped >= 50 && unrecorded >= 50,
            "the table yielded {timestamped} timestamps and {unrecorded} unrecorded rows: the \
             scan is not reading both kinds"
        );
        assert_eq!(
            unrecorded_blocks, 1,
            "the {unrecorded} unrecorded rows form {unrecorded_blocks} separate blocks: they are \
             one stretch of rounds whose moments were never written down, not a hole punched into \
             rows that do have times"
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

    /// The number that follows `label` inside the round's tally sentence.
    ///
    /// The sentence is introduced by `本轮计数：` so that prose which quotes an older or stale
    /// claim - the very thing these rows are about - cannot be mistaken for the tally.
    fn tally(text: &str, label: &str) -> Option<usize> {
        // A row may quote the sentence's shape (`本轮计数：变异 <n> 条…`) while explaining the
        // guard, so every occurrence is tried and the last one that carries a number wins.
        let mut search = 0;
        let mut found = None;
        while let Some(found_at) = text[search..].find("本轮计数：") {
            let at = search + found_at + "本轮计数：".len();
            search = at;
            let Some(label_at) = text[at..].find(label) else {
                continue;
            };
            let digits: String = text[at + label_at + label.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(count) = digits.parse() {
                found = Some(count);
            }
        }
        found
    }

    /// A tally as a round writes it outside the `本轮计数：` sentence.
    ///
    /// Rounds R1-R147 state their counts in Chinese numerals in prose - the revision history
    /// writes `负结果（两条）`, the review log writes `负结果两条（…）` - and only R148 onwards share
    /// the digit sentence `本轮计数：变异 4 条被抓`. A guard that reads digits therefore covers four
    /// rounds out of a hundred and fifty-one and says nothing about the other hundred and
    /// forty-seven, which is how R152's F160 hid: mutating R144's log row from `负结果两条` to
    /// `负结果三条` left the two documents disagreeing and the guard green.
    fn spelled_tally(text: &str, label: &str) -> Option<usize> {
        /// Read one numeral: ASCII digits, `两`, or the Chinese spelling up to ninety-nine.
        fn read_numeral(text: &str) -> Option<(usize, usize)> {
            fn digit_value(ch: char) -> Option<usize> {
                Some(match ch {
                    '零' => 0,
                    '一' => 1,
                    '二' | '两' => 2,
                    '三' => 3,
                    '四' => 4,
                    '五' => 5,
                    '六' => 6,
                    '七' => 7,
                    '八' => 8,
                    '九' => 9,
                    _ => return None,
                })
            }
            let ascii: String = text.chars().take_while(char::is_ascii_digit).collect();
            if !ascii.is_empty() {
                return Some((ascii.parse().ok()?, ascii.len()));
            }
            let mut consumed = 0;
            let mut value = None;
            let mut after_ten = 0usize;
            for ch in text.chars() {
                if ch == '十' {
                    after_ten = value.take().unwrap_or(1) * 10;
                    consumed += ch.len_utf8();
                    continue;
                }
                match digit_value(ch) {
                    Some(digit) => {
                        if after_ten > 0 {
                            after_ten += digit;
                        } else if value.is_none() {
                            value = Some(digit);
                        } else {
                            break;
                        }
                        consumed += ch.len_utf8();
                    }
                    None => break,
                }
            }
            if after_ten > 0 {
                Some((after_ten, consumed))
            } else {
                Some((value?, consumed))
            }
        }

        /// A tally written as `<numeral> 条`, optionally behind an opening parenthesis.
        fn leading_tally(text: &str) -> Option<(usize, usize)> {
            let stripped = text.trim_start_matches(['（', '(', ' ']);
            let skipped = text.len() - stripped.len();
            let (count, used) = read_numeral(stripped)?;
            let tail = &stripped[used..];
            let spaces = tail.len() - tail.trim_start_matches(' ').len();
            if tail[spaces..].starts_with('条') {
                // The reported length covers the numeral, the spaces and `条`, so a caller can
                // ask whether the tally ended exactly where it expected to.
                Some((count, skipped + used + spaces + '条'.len_utf8()))
            } else {
                None
            }
        }

        /// The clause a label sits in: a tally never describes a neighbour's clause.
        fn clause(text: &str) -> &str {
            let cut = text
                .char_indices()
                .find(|(_, ch)| matches!(ch, '；' | '。' | '|' | '\n'))
                .map(|(at, _)| at)
                .unwrap_or(text.len());
            &text[..cut]
        }

        let mut found = None;
        let mut search = 0;
        while let Some(offset) = text[search..].find(label) {
            let at = search + offset;
            search = at + label.len();
            let after = clause(&text[at + label.len()..]);
            let window_end = after
                .char_indices()
                .nth(12)
                .map(|(at, _)| at)
                .unwrap_or(after.len());
            // The tally follows the label directly (`变异四条`) or behind a word or two
            // (`变异实测（三条被抓）`).
            if let Some(count) = after[..window_end]
                .char_indices()
                .find_map(|(at, _)| leading_tally(&after[at..]).map(|(count, _)| count))
            {
                found = Some(count);
                continue;
            }
            // A tally can also be written in front of the label (`两条变异被抓`), and then it
            // has to end where the label begins - otherwise `负结果两条` next door would be read
            // as this label's count, which is exactly how R114 first looked like a disagreement.
            let before = text[..at]
                .rsplit(['；', '。', '|', '\n'])
                .next()
                .unwrap_or_default();
            let prefix_start = before
                .char_indices()
                .rev()
                .nth(8)
                .map(|(at, _)| at)
                .unwrap_or(0);
            let prefix = &before[prefix_start..];
            if let Some(count) = prefix.char_indices().find_map(|(at, _)| {
                let (count, used) = leading_tally(&prefix[at..])?;
                prefix[at + used..].trim_end().is_empty().then_some(count)
            }) {
                found = Some(count);
            }
        }
        found
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

        // A backlog count is a fact with one home. R123 fixed two documents that disagreed
        // about it; R153 found the same fact stated a third time - in REL-01's evidence row -
        // where no guard was watching and where it had been stale for ninety-two commits. The
        // row now points at the registry instead of repeating the number.
        //
        // Only the two tables a reader consults are scanned: the evidence table and the
        // registry. The round-by-round narrative quotes what earlier rounds wrote, and a rule
        // that forbade the phrase there would forbid the plan from describing its own history.
        let evidence = PLAN
            .split("\n## 实施证据汇总\n")
            .nth(1)
            .and_then(|rest| rest.split("\n## Review log\n").next())
            .expect("the plan no longer has an evidence summary section");
        let registry = PLAN
            .split("\n### 依赖登记表\n")
            .nth(1)
            .and_then(|rest| rest.split("\n### ").next())
            .expect("the plan no longer has a dependency registry");
        for (name, section, row) in [
            ("the plan's evidence table", evidence, policy_row),
            ("the plan's dependency registry", registry, policy_row),
        ] {
            for line in section.lines() {
                if line == row || !line.contains("尚未推送") || !line.contains("个提交") {
                    continue;
                }
                panic!(
                    "{name} states the push backlog a second time in another row: {line}. \
                     The count belongs in the DEP-03 row, so reference it from here instead"
                );
            }
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

    /// `download` classifies the remote path it was handed, not what that path points at.
    ///
    /// `walk_remote_dir` was taught to ask for each entry's own attributes, but the caller
    /// still opened with `sftp.metadata` (a following `stat`), so a symlink to a regular file
    /// classified as a file, `download_file` opened it, and the copy held the target's bytes -
    /// a silent follow, on the one path that never reaches the walk. A local `sftp-server`
    /// proves the two requests disagree on the same path (`STAT` answers `perms=0o100644`,
    /// `LSTAT` answers `perms=0o120777`) and that `OPEN` + `READ` on the link returns the
    /// target's bytes. The guard reads `Machine::download` and requires the own-attribute
    /// request plus a link refusal, and rejects the following `stat` coming back.
    #[test]
    fn the_download_root_is_classified_without_following_links() {
        let body = function_body(
            include_str!("machine.rs"),
            "    pub async fn download<P: AsRef<Path>, Q: AsRef<Path>>(",
        );

        let classification = {
            let end = body
                .find("if !remote_meta.is_dir()")
                .expect("`download` no longer branches on the root's type");
            &body[..end]
        };
        assert!(
            classification.matches("symlink_metadata(").count() == 1,
            "the download root has to be stat'ed once, without following links"
        );
        assert!(
            !body.contains("sftp.metadata("),
            "`sftp.metadata` follows links, so a link to a file would be copied as its target"
        );
        assert!(
            classification.contains("cannot download the symbolic link"),
            "a link handed to `download` must be refused by name, not followed"
        );
        assert!(
            classification.contains("file_type().is_symlink()"),
            "the refusal has to be decided from the entry's own attributes"
        );
    }

    /// The plan describes the `copy` command the code actually runs.
    ///
    /// The FS-01 evidence row was written when Windows `copy` still handed a script to
    /// `powershell`'s `-Command` argument. R60 moved the delivery to `-EncodedCommand`
    /// (base64 of UTF-16LE) so the outer shell cannot expand `$` in a path, and R10 dropped a
    /// redundant `-Command "..."` wrapper - but the row kept the old shape, three rows above
    /// the R10 row that describes the new one. A reader comparing the card with the code, or
    /// with the rest of the same table, found two different commands. The guard pins the row
    /// to `copy_file_command` + `-EncodedCommand` and rejects the stale phrase returning.
    #[test]
    fn the_plan_describes_the_copy_command_the_code_runs() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const WINDOWS: &str = include_str!("windows.rs");

        assert!(
            !PLAN.contains("-NonInteractive -Command \"Copy-Item"),
            "that shape predates `-EncodedCommand` and contradicts the row that describes it"
        );

        let card = {
            let start = heading_offset(PLAN, "### Task FS-01:");
            let end = heading_offset(PLAN, "### Task REL-01:");
            assert!(
                start < end,
                "the cards are out of order: the FS-01 slice is empty"
            );
            &PLAN[start..end]
        };
        assert!(
            card.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("powershell -NoProfile -NonInteractive -EncodedCommand"),
            "the FS-01 row has to spell the delivery the code uses, not just mention the flag"
        );
        assert!(
            card.contains("copy_file_command"),
            "the FS-01 row has to name the function that builds the command"
        );
        assert!(
            WINDOWS.contains("powershell_command(&copy_file_script(from, to))"),
            "`copy_file_command` no longer hands the script to `powershell_command`"
        );
    }

    /// `upload` classifies the local path it was handed, not what that path points at.
    ///
    /// The tree branch learned to ask about each entry itself, but the first call still used
    /// `tokio::fs::metadata` - a following `stat` - so a link handed straight to `upload`
    /// looked like the file it points at. The bytes uploaded were the target's, and on a
    /// Windows guest the rule that refuses links never ran, because that branch was never
    /// reached. A local `sftp-server` shows what the guest would have done with the write:
    /// `OPEN(WRITE|CREAT|TRUNC)` on the link answers a handle and the link survived while the
    /// target's bytes were replaced. The guard requires the own-attribute call and one shared
    /// refusal, and rejects a second copy of that refusal message appearing again.
    #[test]
    fn the_upload_root_is_classified_without_following_links() {
        let source = include_str!("machine.rs");
        let body = function_body(
            source,
            "    pub async fn upload<P: AsRef<Path>, Q: AsRef<Path>>(",
        );

        assert!(
            body.matches("symlink_metadata(local_path)").count() == 1,
            "the upload root has to be classified from its own attributes"
        );
        assert!(
            !body.contains("tokio::fs::metadata(local_path)"),
            "`tokio::fs::metadata` follows links, so a link would be uploaded as its target"
        );
        let root = {
            let end = body
                .find("ssh.upload_file(local_path")
                .expect("`upload` no longer sends the file it was handed");
            &body[..end]
        };
        assert!(
            root.contains("if is_link"),
            "a link handed to `upload` has to be decided before it is sent as a file"
        );
        let flat = root.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains(
                "upload_symbolic_link(ssh, os, local_path, &remote_target).await?; return Ok(());"
            ),
            "the link has to be transferred and the call has to end there, not fall through \
             to sending the target's bytes as well"
        );
        assert!(
            source
                .matches("symbolic links are not supported when uploading to a Windows guest")
                .count()
                == 1,
            "the Windows refusal belongs in one place, or the two call sites drift apart"
        );
    }

    /// The README states the symlink rules per guest, and the code keeps them.
    ///
    /// The bullet used to say that uploading a tree with a symlink and downloading one both
    /// fail, then added that on Linux "the link is recreated" - two clauses that contradict
    /// each other and the code, where a Windows upload refuses the link while a Linux upload
    /// recreates it. It also said nothing about a `download` whose own path is a link, which
    /// is exactly the case `download` used to follow. The guard pins each rule to its guest
    /// and to the direction of the copy.
    #[test]
    fn the_readme_states_the_symlink_rules_the_code_implements() {
        const README: &str = include_str!("../README.md");
        let flat = README.split_whitespace().collect::<Vec<_>>().join(" ");

        for sentence in [
            "uploading a link to a Windows guest fails with an error naming the link",
            "whether the link is the path handed to `upload` or an entry inside a tree",
            "uploading to a Linux guest recreates the link on the guest",
            "Downloading never turns a link into its target",
            "or the path the download was asked for, is reported as a link",
        ] {
            assert!(
                flat.contains(sentence),
                "the README no longer states `{sentence}`"
            );
        }
        assert!(
            !flat.contains("uploading a tree that contains a symlink, or downloading one, fails"),
            "that blanket claim is false for Linux uploads and says nothing about the root path"
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
    /// Seven smoke tests are the only place a real Windows guest is exercised.
    ///
    /// The plan's matrix promises that, when the host cannot run them, all seven stop at the
    /// same prerequisite gate instead of one of them skipping it and reporting a pass. That
    /// promise is about the suite, so it has to be checked against the suite: a test that
    /// returned early, built no machine, or forgot the image gate would leave the promise
    /// describing a suite that no longer exists - and a green `--ignored` run would then mean
    /// "nothing to do here" rather than "the gate answered".
    #[test]
    fn every_windows_smoke_test_stops_at_the_prerequisite_gate() {
        const SMOKE: &str = include_str!("../tests/windows_machine.rs");

        let names = [
            "windows_firmware_lifecycle",
            "windows_first_boot",
            "windows_transport",
            "windows_pool",
            "windows_exec",
            "windows_get_ip",
            "windows_files",
        ];
        assert_eq!(names.len(), 7, "the plan counts seven Windows smoke tests");
        assert_eq!(
            SMOKE.matches("#[tokio::test]").count(),
            names.len(),
            "a Windows smoke test was added or removed without updating the plan's count"
        );

        for name in names {
            let signature = format!("async fn {name}(");
            let body = function_body(SMOKE, &signature);
            assert!(
                body.contains("windows_image_config()?"),
                "`{name}` does not ask for the Windows image first, so it may never reach the \
                 prerequisite gate the plan promises it stops at"
            );
            assert!(
                body.contains("Machine::new(") || body.contains("pool.add("),
                "`{name}` builds no machine, so nothing in it can reach the QEMU prerequisites"
            );
            assert!(
                !body.contains("return Ok(())"),
                "`{name}` returns success early, which would let it report a pass without \
                 running the guest it is supposed to exercise"
            );
        }
    }

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

    /// A first boot is one concept with two mechanisms, and both places say so.
    ///
    /// The core interface list is the first thing a reader sees, and it used to describe
    /// `Machine::init` as "first boot with cloud-init" - the rustdoc summary said the same.
    /// Neither is true for `GuestOs::Windows`, whose first boot is a seed-based deployment
    /// with no cloud-init anywhere, and the paragraph directly below that rustdoc summary
    /// describes exactly that. The two summaries are now the same sentence, name both
    /// mechanisms, and the unqualified wording is rejected.
    #[test]
    fn the_ip_smoke_re_queries_after_a_restart() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // The card promised a smoke test for "the cache and a fresh query" while the test only
        // called `get_ip` twice on one running machine - the second call is the cache, so the
        // fresh query the comment, the card bullet and the evidence row all describe was never
        // exercised (F172). The three facts now have to be three assertions.
        let source = CRATE_SOURCES
            .iter()
            .find(|(path, _)| *path == "tests/windows_machine.rs")
            .map(|(_, source)| *source)
            .expect("tests/windows_machine.rs is not in CRATE_SOURCES");
        let body = body_of(source, "async fn windows_get_ip(");
        let queries = body.matches(".get_ip().await").count();
        assert!(
            queries >= 3,
            "the IP smoke makes {queries} `get_ip` calls: the first query, the cache hit and the \
             query after the restart are three"
        );
        let spawn = body
            .find("vm.spawn().await?")
            .expect("the IP smoke no longer restarts the machine before its fresh query");
        let other = body
            .find("let other_ip = other.get_ip().await?")
            .expect("the IP smoke no longer starts a second machine");
        assert!(
            spawn > other,
            "the restart has to happen after the second machine has a lease, otherwise the \
             fresh query proves nothing about the MAC filter"
        );
        assert!(
            body[spawn..].contains("assert_eq!(\n        vm.get_ip().await?,\n        ip,"),
            "the query after the restart is not compared with the address of the same VM"
        );

        // The card and the test have to describe the same three facts; a card that promises a
        // re-query over a test that has none is the defect this round fixed.
        let lines: Vec<&str> = PLAN.lines().collect();
        let start = lines
            .iter()
            .position(|line| line.starts_with("### Task IP-01"))
            .expect("the plan has no IP-01 card")
            + 1;
        let end = lines[start..]
            .iter()
            .position(|line| line.starts_with("### Task ") || line.starts_with("## "))
            .map(|offset| start + offset)
            .expect("the IP-01 card runs to the end of the document");
        let card = lines[start..end]
            .iter()
            .find(|line| line.starts_with("| 集成测试（`#[ignore]`） |"))
            .expect("the IP card no longer lists its integration test");
        for phrase in ["首查", "缓存复读", "双机地址互异", "重启后重查"] {
            assert!(
                card.contains(phrase),
                "the IP card's integration-test row no longer mentions `{phrase}`: {card}"
            );
        }
        // The comment above the test is what a reader believes; the assertion message inside it
        // mentions a restart too, so checking the body would pass on the message alone.
        let signature = source
            .find("async fn windows_get_ip(")
            .expect("the IP smoke no longer exists");
        let doc: Vec<&str> = source[..signature]
            .lines()
            .rev()
            .skip_while(|line| line.trim_end().is_empty())
            // Attributes sit between the comment and the signature; a scan that stops at the
            // first non-`///` line stops before it has read anything at all.
            .take_while(|line| {
                let line = line.trim_start();
                line.starts_with("///") || line.starts_with("#[")
            })
            .filter(|line| line.trim_start().starts_with("///"))
            .collect();
        assert!(
            doc.iter().any(|line| line.contains("restart")),
            "the IP smoke's own comment no longer says what the restart is for"
        );
    }

    /// `## 兼容与文档收口` mixes finished audits with one item that waits for the release.
    ///
    /// Two of the finished audits sat in unchecked boxes, so a reader walking the section
    /// could not tell "verified, nothing to do" from "not looked at yet" - and the plan's own
    /// completion criterion is that this section is closed except for the release. The
    /// directory list next to them was a hand-copied `ls tests/`, which goes stale the moment
    /// an integration test file is added (R171).
    #[test]
    fn the_compatibility_section_keeps_no_unchecked_item_but_the_release() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let section = section(PLAN, "## 兼容与文档收口");
        let unchecked: Vec<&str> = section
            .lines()
            .filter(|line| line.starts_with("- [ ]"))
            .collect();
        assert_eq!(
            unchecked.len(),
            1,
            "only the 0.4.0 CHANGELOG entry may stay open in this section, and it must: {unchecked:#?}"
        );
        assert!(
            unchecked[0].contains("CHANGELOG 按 Keep a Changelog"),
            "the one open box must be the release item, not an audit that is already done: {}",
            unchecked[0]
        );
    }

    /// The plan's inventory of `tests/` must be the directory's, not a memory of it.
    ///
    /// A hand-written list of filenames cannot report its own staleness: adding
    /// `tests/windows_something.rs` leaves the sentence claiming a five-file directory looking
    /// correct. This reads the directory and compares both ways, so the sentence can only be
    /// right when someone updates it (R171).
    #[test]
    fn the_tests_directory_list_names_every_file_there() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        let row = section(PLAN, "## 兼容与文档收口")
            .lines()
            .find(|line| line.contains("`tests/INDEX.md`"))
            .expect("the compatibility section lost its `tests/INDEX.md` row");

        let mut on_disk: Vec<String> =
            std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests"))
                .expect("the tests directory must exist")
                .map(|entry| entry.expect("a readable directory entry").file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".rs"))
                .collect();
        on_disk.sort();
        assert!(
            on_disk.len() >= 5,
            "the guard read {on_disk:?}; it is not looking at the integration tests"
        );
        for name in &on_disk {
            assert!(
                row.contains(&format!("`{name}`")),
                "`tests/{name}` exists but the plan's inventory does not name it: {row}"
            );
        }
        // The other direction: a name in the sentence that is no longer a file is a stale
        // entry, which is the same defect seen from the other side.
        for quoted in row.split('`').skip(1).step_by(2) {
            // Only a filename counts: the sentence also mentions the bare suffix `.rs` when it
            // says what the guard compares, and that is not an inventory entry.
            let looks_like_a_file = quoted.len() > 4
                && quoted.ends_with(".rs")
                && quoted[..quoted.len() - 3]
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
            if looks_like_a_file && !on_disk.iter().any(|name| name == quoted) {
                panic!("the inventory names `{quoted}`, which is not in `tests/`: stale entry");
            }
        }
    }

    #[test]
    fn the_blank_command_refusal_is_tested_where_it_can_run() {
        const MACHINE: &str = include_str!("../src/machine.rs");
        const README: &str = include_str!("../README.md");
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // Two documents promise the refusal; the plan's card used to say the unit tests only
        // covered exit codes, leaving the refusal to an `#[ignore]` smoke that needs a real
        // Windows guest for a check that needs no guest at all (R170).
        assert!(
            MACHINE.contains("async fn a_blank_command_is_refused_before_a_session_is_looked_up()"),
            "the unit test for the blank-command refusal is gone"
        );
        let exec = function_body(MACHINE, "pub async fn exec<S: AsRef<str>>");
        assert!(
            exec.contains("cmd_ref.trim().is_empty()") && exec.contains("bail!("),
            "`Machine::exec` no longer refuses a blank command before opening a session"
        );
        assert!(
            README.contains(
                "An empty or whitespace-only command is rejected with an error before any SSH \
                 request is\n  sent."
            ) || README.contains(
                "An empty or whitespace-only command is rejected with an error before any SSH request is"
            ),
            "the README no longer states that a blank command is rejected before any SSH request"
        );
        // And the card must not claim the refusal is only covered by the ignored smoke.
        let card = section(PLAN, "### Task EXE-01: PowerShell `exec` 语义");
        let row = card
            .lines()
            .find(|line| line.starts_with("| 单测 |"))
            .expect("the EXE-01 evidence table lost its unit-test row");
        assert!(
            row.contains("a_blank_command_is_refused_before_a_session_is_looked_up"),
            "the EXE-01 unit-test row does not name the blank-command test: {row}"
        );
    }

    #[test]
    fn the_liveness_refusal_is_an_error_in_the_branch_and_in_the_changelog() {
        const MACHINE: &str = include_str!("../src/machine.rs");
        const CHANGELOG: &str = include_str!("../CHANGELOG.md");
        // A live process without a control socket is the one answer that must never be `false`:
        // `false` is what callers read as "this run directory is free".
        let body = function_body(MACHINE, "pub async fn is_running(&self) -> Result<bool>");
        let arm = body
            .split("RunningCheck::LiveWithoutSocket =>")
            .nth(1)
            .expect("`is_running` no longer has a branch for a live QEMU without a socket");
        assert!(
            arm.trim_start().starts_with("bail!("),
            "the live-process-without-socket branch now answers instead of refusing: {arm}"
        );
        // The CHANGELOG tells users the same thing; if the branch changes, that sentence is a
        // lie and this equality is the only thing that would notice.
        assert!(
            CHANGELOG.contains(
                "a live process without a socket is an error, so a second QEMU cannot be \
                 started on the same disk"
            ),
            "the CHANGELOG no longer states that a live process without a socket is an error"
        );
        // And the three answers are covered by tests that run without QEMU (R169).
        for name in [
            "is_running_refuses_a_live_qemu_that_lost_its_socket",
            "is_running_answers_false_when_the_recorded_pid_is_no_longer_our_qemu",
            "is_running_answers_false_for_a_machine_that_never_started",
        ] {
            assert!(
                MACHINE.contains(&format!("async fn {name}()")),
                "the liveness test `{name}` is gone, so `is_running` lost a covered answer"
            );
        }
    }

    #[test]
    fn the_knob_that_keeps_a_run_directory_says_what_it_keeps() {
        const MACHINE: &str = include_str!("../src/machine.rs");
        const README: &str = include_str!("../README.md");
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // The failure-recovery matrix sends a reader to `clear = false` to keep a failed run
        // directory "for diagnosis". Nothing said that the directory holds the seed medium and
        // with it the per-VM SSH host private key, and nothing said Qlean never removes it
        // afterwards - so the documented diagnostic knob also documented nothing about the key
        // material it keeps on disk (F177).
        // The rustdoc block directly above the field, collected upwards: a field has no body
        // for `function_body` to scan, and the nearby `{`-blocks belong to other items.
        let lines: Vec<&str> = MACHINE.lines().collect();
        let field_line = lines
            .iter()
            .position(|line| line.trim() == "pub clear: bool,")
            .expect("`MachineConfig::clear` is gone");
        let mut field = String::new();
        for above in lines[..field_line].iter().rev() {
            let above = above.trim();
            if !above.starts_with("///") {
                break;
            }
            field = format!("{above}\n{field}");
        }
        assert!(
            !field.is_empty(),
            "`MachineConfig::clear` has no rustdoc left"
        );
        for fact in ["seed medium", "private key", "caller's job"] {
            assert!(
                field.contains(fact),
                "`MachineConfig::clear` no longer says `{fact}` about the directory it keeps"
            );
        }
        // The README is what a user reads before writing code; the code block alone (a struct
        // with a `clear: bool`) never explained the trade-off.
        let readme_section = README
            .split("### Diagnostics: keeping the run directory")
            .nth(1)
            .expect("the README has no section about keeping the run directory");
        let readme_section = readme_section
            .split("\n### ")
            .next()
            .expect("the section runs to the next heading");
        for fact in [
            "MachineConfig::with_clear(false)",
            "host private key",
            "never cleaned up",
        ] {
            assert!(
                readme_section.contains(fact),
                "the README section about keeping the run directory no longer says `{fact}`"
            );
        }
        // And the matrix row that recommends it has to name the actual API, not a bare `clear=false`.
        let row = PLAN
            .lines()
            .find(|line| line.starts_with("| Windows 首启后重启失败 |"))
            .expect("the recovery matrix lost its failed-restart row");
        assert!(
            row.contains("MachineConfig::with_clear(false)"),
            "the matrix row recommends keeping the run directory without naming the API: {row}"
        );
    }

    #[test]
    fn the_failed_launch_teardown_is_written_once_and_is_bounded() {
        const MACHINE: &str = include_str!("../src/machine.rs");
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // Three failure exits of a launch have to leave the same four facts behind, and one of
        // them used to await the launch task without a budget while its siblings bounded it:
        // a wedged QEMU could hide the original error behind a hang (F176).
        let body = function_body(MACHINE, "async fn tear_down_failed_launch<T>");
        assert!(
            body.contains("reap_launch_task(qemu_handle"),
            "the shared launch teardown no longer reaps the launch task through the bounded helper"
        );
        for step in [
            "self.ssh = None;",
            "self.pid.take()",
            "swtpm.stop()",
            "terminate_qemu",
        ] {
            assert!(
                body.contains(step),
                "the shared launch teardown no longer performs `{step}`"
            );
        }
        assert_eq!(
            MACHINE.matches("fn tear_down_failed_launch").count(),
            1,
            "the launch teardown was copied instead of shared"
        );
        let callers = MACHINE
            .matches("self.tear_down_failed_launch(qemu_handle)")
            .count();
        assert!(
            callers >= 3,
            "only {callers} failure exits of a launch use the shared teardown; the lease, the \
             deployment confirmation and the SSH session are its three callers"
        );
        // No path may await the launch task directly again: the bounded reaper is the only
        // way to wait for it, and the one direct await left is the already-finished branch.
        for line in MACHINE.lines() {
            if !line.contains("qemu_handle.await") {
                continue;
            }
            assert!(
                line.contains("qemu_exit_before_lease(") || line.contains("reap_launch_task("),
                "the launch task is awaited outside the bounded reaper: {}",
                line.trim()
            );
        }
        let tests = test_names_in(&[("src/machine.rs", MACHINE)]);
        assert!(
            tests
                .iter()
                .any(|name| name.contains("a_failed_launch_teardown_leaves_nothing_behind")),
            "the shared launch teardown has no test of its own"
        );
        // The recovery matrix is the contract a reader trusts; it has to name the mechanism.
        // Slice the matrix out by its heading: the same phrase is quoted in the revision
        // history and the review log, and a whole-document search would find those instead.
        let lines: Vec<&str> = PLAN.lines().collect();
        let matrix_start = lines
            .iter()
            .position(|line| line.trim_end() == "### 故障恢复矩阵")
            .expect("the plan has no recovery matrix");
        let matrix_end = matrix_start
            + 1
            + lines[matrix_start + 1..]
                .iter()
                .position(|line| line.starts_with("### ") || line.starts_with("## "))
                .expect("the recovery matrix runs to the end of the document");
        let matrix: Vec<&str> = lines[matrix_start..matrix_end]
            .iter()
            .filter(|line| line.starts_with("| ") && line.contains("统一失败分支"))
            .copied()
            .collect();
        assert_eq!(
            matrix.len(),
            1,
            "the recovery matrix lost its launch-failure row"
        );
        assert!(
            matrix[0].contains("tear_down_failed_launch") && matrix[0].contains("reap_launch_task"),
            "the recovery matrix describes the launch failure without naming the shared \
             teardown and its bounded reaper: {}",
            matrix[0]
        );
    }

    #[test]
    fn the_rollback_table_says_how_its_counts_can_be_recomputed() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // The rollback table lists how many files each card's revert stages. Those numbers were
        // measured once, by hand, and one of them was wrong for a hundred rounds (8 where the
        // revert stages 9) because nothing said how to measure them again (F175).
        let lines: Vec<&str> = PLAN.lines().collect();
        let start = lines
            .iter()
            .position(|line| line.trim_end() == "### 回滚操作步骤与实测证据")
            .expect("the plan has no rollback section");
        let end = start
            + 1
            + lines[start + 1..]
                .iter()
                .position(|line| line.starts_with("### ") || line.starts_with("## "))
                .expect("the rollback section runs to the end of the document");
        let section = lines[start..end].join("\n");

        assert!(
            section.contains("libra show --name-only") && section.contains("不必再跑回滚"),
            "the rollback table no longer says how its file counts can be recomputed, so a \
             wrong number can live on unnoticed"
        );

        let rows: Vec<&str> = lines[start..end]
            .iter()
            .filter(|line| {
                line.starts_with("| ") && !line.starts_with("| 卡 ") && !line.starts_with("|---")
            })
            .copied()
            .collect();
        assert_eq!(
            rows.len(),
            8,
            "the rollback table covers seven cards plus the last code commit; it now lists {} rows",
            rows.len()
        );
        let mut subjects = 0;
        for row in &rows {
            let cells: Vec<&str> = row.trim_matches('|').split('|').collect();
            let label = cells[0].trim();
            let hash = cells[1].trim().trim_matches('`');
            assert_eq!(
                hash.len(),
                7,
                "the rollback row for `{label}` does not name a seven-character commit"
            );
            // Seven card rows have to be the same commits the evidence summary credits; the
            // eighth row is the last code commit, which the summary does not list per card.
            if label.starts_with("R102") {
                continue;
            }
            let summary_start = lines
                .iter()
                .position(|line| line.trim_end() == "## 实施证据汇总")
                .expect("the plan has no evidence summary");
            let summary_end = summary_start
                + 1
                + lines[summary_start + 1..]
                    .iter()
                    .position(|line| line.starts_with("## "))
                    .expect("the evidence summary runs to the end of the document");
            // Searching the whole plan would find the hash in the row itself and prove nothing.
            let summary = lines[summary_start..summary_end].join("\n");
            assert!(
                summary.contains(&format!("`{hash}`")),
                "the rollback row for `{label}` names `{hash}`, which the evidence summary never \
                 credits - a subject that only this table knows about"
            );
            subjects += 1;
        }
        assert_eq!(
            subjects, 7,
            "the rollback table no longer covers the seven cards"
        );
    }

    #[test]
    fn the_retry_rule_for_a_failed_launch_is_stated_once_and_has_a_test() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // "A failed launch can be retried" was a rule written twice inline - once in `init` and
        // once in `spawn` - and described in the card as if a test covered it. Two copies of one
        // rule drift, and the recovery action the failure matrix promises had no test at all
        // (F174).
        let source = CRATE_SOURCES
            .iter()
            .find(|(path, _)| *path == "src/machine.rs")
            .map(|(_, source)| *source)
            .expect("src/machine.rs is not in CRATE_SOURCES");
        let inline =
            "self.ssh_cancel_token.is_some() && (self.pid.is_some() || self.ssh.is_some())";
        // The one allowed copy is inside the predicate itself, so count outside its body.
        let helper_body = body_of(source, "fn already_started(&self)");
        let outside = source.replace(&helper_body, "");
        assert_eq!(
            outside.matches(inline).count(),
            0,
            "the retry rule is inline again: a second copy drifts from `already_started`"
        );
        assert_eq!(
            source.matches("fn already_started(&self)").count(),
            1,
            "the retry rule needs exactly one implementation"
        );
        assert!(
            source.matches("self.already_started()").count() >= 2,
            "`init` and `spawn` both have to ask the same predicate"
        );
        let retried = body_of(
            source,
            "async fn a_failed_launch_leaves_a_machine_that_can_be_started_again",
        );
        assert!(
            retried.contains("abandon_launch()") && retried.contains("!machine.already_started()"),
            "the test no longer walks the failed launch into a retryable machine"
        );

        // The promise in the plan has to name the predicate, so a reader can find the code.
        for phrase in [
            "失败启动可重试",
            "`init`/`spawn` 在启动失败时取消并清除 cancel token",
        ] {
            assert!(
                PLAN.lines()
                    .any(|line| line.contains(phrase) && line.contains("already_started")),
                "the plan no longer names `already_started` where it promises `{phrase}`"
            );
        }
        let recovery = PLAN
            .lines()
            .find(|line| {
                line.starts_with("| `init`/`spawn` 启动失败（含首启超时、`read_pid` 失败）")
            })
            .expect("the failure matrix no longer has the failed-launch row");
        assert!(
            recovery.contains("`already_started`"),
            "the failure matrix promises a retry without naming the rule that allows it: {recovery}"
        );
    }

    #[test]
    fn the_two_matrix_rows_about_the_revision_history_agree_about_its_time_column() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // Two rows of the test matrix describe the same guard. R161 taught the time column to say
        // `不可回溯` instead of an estimate; one of those two rows kept promising that every row
        // carries a timestamp, so the same table made two opposite claims about one test (F173).
        let lines: Vec<&str> = PLAN.lines().collect();
        let start = lines
            .iter()
            .position(|line| line.trim_end() == "## 测试矩阵")
            .expect("the plan has no test matrix");
        let end = start
            + 1
            + lines[start + 1..]
                .iter()
                .position(|line| line.starts_with("## "))
                .expect("the test matrix runs to the end of the document");
        let rows: Vec<&&str> = lines[start..end]
            .iter()
            .filter(|line| line.contains("the_plan_revision_history_is_ordered_newest_first"))
            .collect();
        assert!(
            rows.len() >= 2,
            "the matrix rows about this guard went missing"
        );

        let mut states_the_marker = 0;
        for row in &rows {
            assert!(
                !(row.contains("每一行都有") && row.contains("HH:MM:SS")),
                "a matrix row still promises a timestamp on every revision-history row, but the \
                 table says `{HISTORY_UNRECORDED}` where the moment was never recorded: {row}"
            );
            if row.contains(HISTORY_UNRECORDED) {
                states_the_marker += 1;
            }
        }
        assert!(
            states_the_marker >= 1,
            "no matrix row states the marker rule any more: the table would be back to implying \
             that every row carries a time"
        );
    }

    #[test]
    fn the_plan_and_the_code_agree_on_how_many_failures_end_the_marker_wait() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        // The failure-recovery matrix and the test matrix both promise a number ("three
        // consecutive failures"), and the loop has to stop on exactly that number. A constant in
        // one file and the same number spelled out in another are two facts until something
        // compares them.
        let machine = CRATE_SOURCES
            .iter()
            .find(|(path, _)| *path == "src/machine.rs")
            .map(|(_, source)| *source)
            .expect("src/machine.rs is not in CRATE_SOURCES");
        let limit = number_after(machine, "MAX_CONSECUTIVE_MARKER_ERRORS: u32 = ")
            .expect("the marker wait no longer declares how many failures end it")
            .to_owned();

        let mut checked = 0;
        for line in PLAN.lines() {
            let mut rest = line;
            while let Some(at) = rest.find("连续 ") {
                let before = rest[..at].chars().next_back();
                let after = &rest[at + "连续 ".len()..];
                let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
                let quoted = after[digits.len()..].starts_with(" 次」");
                rest = after;
                // This document quotes its own mutations (`「连续 5 次」`) when it describes them;
                // a quotation is not a promise about the code.
                if digits.is_empty()
                    || !after[digits.len()..].starts_with(" 次")
                    || quoted
                    || before == Some('「')
                {
                    continue;
                }
                checked += 1;
                assert_eq!(
                    digits, limit,
                    "the plan promises {digits} consecutive failures but the code gives up after \
                     {limit}: {line}"
                );
            }
        }
        assert!(checked >= 2, "the plan states the number {checked} times");

        // The rule lives in `MarkerWatch`; a literal comparison in the loop would be a second
        // place to change and would drift from the constant above.
        let wait = body_of(machine, "pub(crate) async fn confirm_deployment(");
        // The condition has to be the verdict itself: `false && watch.observe(..)` mentions the
        // name and never gives up, and a guard that only greps for the name would pass it.
        assert_eq!(
            wait.matches("if watch.observe(marker_poll_outcome(&poll)) {")
                .count(),
            1,
            "the deployment wait no longer ends on what MarkerWatch decides"
        );
        assert!(
            !wait.contains(">= 3"),
            "the deployment wait compares against a literal three instead of the constant"
        );
    }

    #[test]
    fn a_first_boot_is_described_the_same_way_in_the_library_and_the_readme() {
        const README: &str = include_str!("../README.md");
        let bullet = README
            .lines()
            .find(|line| line.starts_with("- `Machine::init()`"))
            .expect("the README must keep `Machine::init()` in the core interface list");
        let documented = bullet
            .split_once(" - ")
            .map(|(_, rest)| rest.trim())
            .expect("the core interface list pairs every method with a description");

        let source = include_str!("machine.rs");
        let summary = source
            .lines()
            .find(|line| line.trim_start().starts_with("/// Initialize the machine"))
            .expect("`Machine::init` must keep a doc summary")
            .trim()
            .strip_prefix("///")
            .expect("a doc summary line starts with `///`")
            .trim();

        assert_eq!(
            documented, summary,
            "the README and the rustdoc describe the first boot differently"
        );
        assert!(
            summary.contains("cloud-init on Linux")
                && summary.contains("deployment seed on Windows"),
            "`init` is a different first boot per guest and the summary must say which: {summary}"
        );
        // No separate "must not say `cloud-init` alone" assertion: the clause above already
        // fails on that wording, and a guard whose branch cannot be reached is not a guard.
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
            // In the history table only the first cell is a date claim; the other cells recount
            // older rounds and quote the dates they were about. Outside it, a date inside backticks
            // is a quotation too - the prose explaining the fabricated ladder quotes it.
            let owned: String;
            let scanned: &str = if in_history && line.starts_with('|') {
                line.split('|').nth(1).unwrap_or("")
            } else {
                owned = line
                    .split('`')
                    .enumerate()
                    .filter(|(index, _)| index % 2 == 0)
                    .map(|(_, text)| text)
                    .collect();
                owned.as_str()
            };
            if scanned.contains(HISTORY_UNRECORDED) {
                continue;
            }
            let bytes = scanned.as_bytes();
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
                     have been observed on that day yet: {scanned}"
                );
            }
        }
        assert!(
            checked >= 50,
            "the plan yielded only {checked} dates: the scan is not looking at them"
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

    /// A document in the plan is cited by a heading, not by a line number.
    ///
    /// R127 taught the `src/<file>.rs:<a>-<b>` citations to stay inside their files; the same
    /// hand-typed form was used four times for documents, and every one of them had rotted by
    /// R172: the network row pointed at host-key pinning, the "0.3.0 dropped the TCP fallback"
    /// row at `0.2.3`, the migration row at the interactive shell, and the changelog row at
    /// whatever followed `[Unreleased]` that week. A source file only moves when someone edits
    /// it; a changelog or a README gains lines every round. The rule is now mechanical: a `.md`
    /// mention may not carry a line number, and a cell that names a heading must name one that
    /// the document still has.
    #[test]
    fn a_document_in_the_plan_is_cited_by_a_heading_not_by_a_line_number() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        for line in PLAN.lines() {
            let mut rest = line;
            while let Some(at) = rest.find(".md:") {
                let after = &rest[at + 4..];
                if after.starts_with(|c: char| c.is_ascii_digit()) {
                    panic!(
                        "the plan cites a markdown line range, which rots as the file grows: {line}"
                    );
                }
                rest = after;
            }
        }

        let document = |name: &str| -> Option<&'static str> {
            if name.ends_with("CHANGELOG.md") {
                Some(include_str!("../CHANGELOG.md"))
            } else if name.ends_with("README.md") {
                Some(include_str!("../README.md"))
            } else if name.ends_with("plan-template.md") {
                Some(include_str!("../docs/plan/plan-template.md"))
            } else if name.ends_with("plan-status.md") {
                Some(include_str!("../docs/plan/plan-status.md"))
            } else {
                None
            }
        };

        let mut checked = 0_usize;
        for line in PLAN.lines() {
            let mut rest = line;
            while let Some(at) = rest.find(".md`") {
                let name = rest[..at + 3]
                    .rsplit_once(['`', ' ', '/'])
                    .map(|(_, name)| name)
                    .unwrap_or(&rest[..at + 3]);
                let tail = &rest[at + 4..];
                let cell = &tail[..tail.find('|').unwrap_or(tail.len())];
                rest = &rest[at + 4..];

                // A heading is attributed to a document only when it follows the name
                // directly (`\`README.md\` 的 \`## Network Configuration\``, or a second
                // heading joined by `与`). A `## ...` heading mentioned elsewhere in the same
                // cell belongs to whatever that sentence is about.
                let mut after = cell.trim_start();
                while let Some(connector) = after
                    .strip_prefix('的')
                    .or_else(|| after.strip_prefix('与'))
                {
                    let Some(quoted) = connector.trim_start().strip_prefix('`') else {
                        break;
                    };
                    let Some((token, remainder)) = quoted.split_once('`') else {
                        break;
                    };
                    // Historical rows name a section in prose
                    // (`\`CHANGELOG.md\` 的 \`[Unreleased]\``) rather than citing a heading;
                    // only a `#`-prefixed token is a citation this guard can resolve.
                    if !(token.starts_with("## ") || token.starts_with("### ")) {
                        break;
                    }
                    let body = document(name).unwrap_or_else(|| {
                        panic!("`{name}` is cited with a heading but is not a registered document")
                    });
                    // A heading may carry a release date after its name, so the citation
                    // has to be a prefix that ends at a word boundary.
                    let found = body.lines().any(|line| {
                        let line = line.trim_end();
                        line == token
                            || line
                                .strip_prefix(token)
                                .is_some_and(|rest| rest.starts_with(' '))
                    });
                    assert!(
                        found,
                        "the plan points `{name}` at `{token}`, which that document no longer has"
                    );
                    checked += 1;
                    after = remainder.trim_start();
                }
            }
        }
        assert!(
            checked >= 4,
            "only {checked} heading citations were checked, so the scan is not reading the plan"
        );
    }

    /// A CID allocation that cannot count past the ceiling is refused, not panicked.
    ///
    /// `utils::get_free_cid` reads the highest `cid` under the runs directory and adds one. The
    /// file is Qlean's own, but the directory is a caller's: it can be copied, restored from a
    /// backup, or edited. At the ceiling, `+ 1` panics inside the library in a debug build and
    /// wraps to `0` (a reserved CID the host cannot dial) in a release build - so the two ways of
    /// failing are "crash the caller" and "boot a guest nothing can reach". The check is one
    /// `checked_add`, so the guard pins the check, the constant it compares against, the three
    /// tests that exercise it, and the changelog sentence that tells a reader why the launch
    /// stopped. Removing the sentence is not compliance: the tests read the real function.
    #[test]
    fn the_cid_allocation_refuses_a_value_it_cannot_count_past() {
        const UTILS: &str = include_str!("../src/utils.rs");
        const CHANGELOG: &str = include_str!("../CHANGELOG.md");

        assert!(
            UTILS.contains("const LAST_GUEST_CID: u32 = u32::MAX - 1;"),
            "the ceiling must stay one below `VMADDR_CID_ANY`"
        );
        let alloc_body = UTILS
            .split("fn get_free_cid(")
            .nth(1)
            .and_then(|rest| rest.split("debug!(\"Our new CID").next())
            .expect("`get_free_cid` or its final trace line is gone");
        let allocation = alloc_body;
        assert!(
            allocation.contains("checked_add(1)") && allocation.contains("<= LAST_GUEST_CID"),
            "the allocation must refuse a CID it cannot count past"
        );
        assert!(
            !allocation.contains("+ 1"),
            "the allocation must not add to an untrusted value unchecked"
        );

        let tests = [
            "test_a_cid_at_the_ceiling_is_refused_instead_of_overflowing",
            "test_the_next_cid_follows_the_highest_one_and_starts_above_the_reserved_range",
            "test_an_unparsable_cid_names_the_file_it_came_from",
        ];
        for name in tests {
            assert!(
                UTILS.contains(&format!("fn {name}(")),
                "`{name}` is part of this card's proof and no longer exists"
            );
        }

        let unreleased = CHANGELOG
            .split("## [Unreleased]")
            .nth(1)
            .and_then(|rest| rest.split("\n## [").next())
            .expect("the changelog must still have an [Unreleased] section");
        let fixed = changelog_sections(unreleased)
            .into_iter()
            .find(|(title, _)| title == "Fixed")
            .expect("the unreleased changelog has no `### Fixed` section")
            .1;
        assert!(
            fixed
                .iter()
                .any(|entry| entry.contains("Allocating a guest CID")),
            "the refusal is user-visible - a launch stops - and the changelog does not say so"
        );
    }

    /// Every device name the README names is a name the code actually reserves.
    ///
    /// The README lists examples of the reserved names rather than all of them, so the list in
    /// `guest_path` is the authority. Nothing tied the two together: an example could name a
    /// device the validator happily accepts, which tells a user their path is refused while the
    /// path works - or, worse, the other way round once the list is trimmed.
    #[test]
    fn the_device_names_the_readme_names_are_the_ones_the_code_reserves() {
        const README: &str = include_str!("../README.md");
        const GUEST_PATH: &str = include_str!("../src/guest_path.rs");

        let sentence = README
            .split("reserved device names (")
            .nth(1)
            .expect("the README no longer lists reserved device names");
        let list = &sentence[..sentence
            .find(')')
            .expect("the example list is unterminated")];
        let named: Vec<&str> = list
            .split(',')
            .map(|name| name.trim().trim_matches('`'))
            .filter(|name| !name.is_empty() && *name != "...")
            .collect();
        assert!(
            named.len() >= 4,
            "the README should name several examples, not {named:?}"
        );

        let reserved = GUEST_PATH
            .split("const WINDOWS_RESERVED_NAMES")
            .nth(1)
            .and_then(|rest| rest.split("= [").nth(1))
            .and_then(|rest| rest.split(']').next())
            .expect("`guest_path` no longer keeps a reserved-name list");
        for name in named {
            assert!(
                reserved.contains(&format!("\"{name}\"")),
                "README.md names `{name}` as a reserved device, but `WINDOWS_RESERVED_NAMES` does not list it"
            );
        }
    }

    /// `CRATE_SOURCES` lists every crate source that exists, and nothing that does not.
    ///
    /// The list is hand-written, so a new module under `src/` would silently sit outside every
    /// guard that walks it: the guards would keep passing while covering one file fewer, and no
    /// test would say so - a hand-written list cannot report that it has gone stale. Only `src/`
    /// is required to be complete: it is the crate, and every file in it is compiled. The other
    /// integration suites under `tests/` are Linux suites the plan never reasons about
    /// (`DEFER-04`), so listing them is optional but naming a file that is not there is not.
    #[test]
    fn the_guarded_source_list_covers_every_crate_source() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

        let listed: Vec<&str> = CRATE_SOURCES.iter().map(|(name, _)| *name).collect();

        let mut on_disk: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(root.join("src")).expect("the crate has a `src` directory") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("a source file name is UTF-8");
                on_disk.push(format!("src/{name}"));
            }
        }
        on_disk.sort();

        let mut missing = on_disk.clone();
        missing.retain(|name| !listed.contains(&name.as_str()));
        assert!(
            missing.is_empty(),
            "these crate sources exist but no guard reads them, so add them to `CRATE_SOURCES`: {missing:?}"
        );

        let mut absent: Vec<&str> = listed
            .iter()
            .copied()
            .filter(|name| !root.join(name).is_file())
            .collect();
        absent.sort_unstable();
        assert!(
            absent.is_empty(),
            "`CRATE_SOURCES` names sources that are not there: {absent:?}"
        );
    }

    /// The budgets the README promises are the ones the code uses.
    ///
    /// `README.md` is the only place a reader learns how long a Windows first boot may take: "The
    /// deployment budget is 900s by default (independent of the Linux SSH connect timeout of
    /// 180s/300s)". The three numbers are hand-typed, the code keeps them in three unrelated
    /// places - `windows::DEPLOY_TIMEOUT_SECS` and the two branches of
    /// `machine::resolve_ssh_timeout` - and nothing compared them, so raising the deployment
    /// budget would leave the README telling a user to give up at the old number of seconds. The
    /// CHANGELOG is exempt on purpose: a release note narrates the release it describes, and its
    /// historical rows quote the budgets as they were.
    #[test]
    fn the_budgets_the_readme_promises_are_the_ones_the_code_uses() {
        const README: &str = include_str!("../README.md");
        const MACHINE: &str = include_str!("../src/machine.rs");

        let number_after = |text: &'static str, marker: &str| -> u64 {
            let rest = text
                .split(marker)
                .nth(1)
                .unwrap_or_else(|| panic!("the README no longer states \"{marker}\""));
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().unwrap_or_else(|_| {
                panic!("`{marker}` is not followed by a number of seconds any more: {rest:.40}")
            })
        };

        // The deployment budget: one constant, stated once in prose.
        assert_eq!(
            number_after(README, "The deployment budget is "),
            crate::windows::DEPLOY_TIMEOUT_SECS,
            "README.md promises a deployment budget the code does not use"
        );

        // The Linux connect budget: two branches, stated as `180s/300s`.
        let pair = README
            .split("Linux SSH connect timeout of ")
            .nth(1)
            .expect("the README no longer contrasts the deployment budget with the connect one");
        let pair = &pair[..pair.find(')').unwrap_or(pair.len())];
        let stated: Vec<u64> = pair
            .split('/')
            .map(|part| {
                let digits: String = part.chars().filter(|c| c.is_ascii_digit()).collect();
                digits
                    .parse()
                    .unwrap_or_else(|_| panic!("`{pair}` does not pair two budgets"))
            })
            .collect();
        assert_eq!(stated.len(), 2, "the connect budget is a pair: `{pair}`");

        let resolved = MACHINE
            .split("fn resolve_ssh_timeout(")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("`machine::resolve_ssh_timeout` is gone");
        let literal = |marker: &str| -> u64 {
            let rest = resolved
                .split(marker)
                .nth(1)
                .unwrap_or_else(|| panic!("`resolve_ssh_timeout` no longer has \"{marker}\""));
            let after = rest
                .split("Duration::from_secs(")
                .nth(1)
                .unwrap_or_else(|| {
                    panic!("the branch at \"{marker}\" no longer builds a `Duration` from seconds")
                });
            let digits: String = after
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            digits.parse().unwrap_or_else(|_| {
                panic!("the branch at \"{marker}\" is not a literal number of seconds")
            })
        };
        let kvm = literal("if is_kvm_available() {");
        let plain = literal("} else {");
        assert_eq!(
            stated,
            vec![kvm, plain],
            "README.md promises {stated:?} for the Linux connect budget but the code uses {kvm}/{plain}"
        );
    }

    /// The traceability table points at names, not at line numbers.
    ///
    /// R127 taught this table's numbers to stay inside their files, which kept them syntactically
    /// valid and let them rot semantically: after ten implementation cards, the row that used to
    /// point at `Machine::exec` pointed at a `let` binding in a test, and nothing objected. R79
    /// fixed the same rot in the baseline table by pinning it to a commit; a table that is read
    /// as "where this lives" cannot carry a snapshot, so its anchors are symbols. The symbol scan
    /// above then keeps them honest.
    #[test]
    fn the_traceability_table_points_at_symbols_not_at_line_numbers() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");

        let table = PLAN
            .split("\n## 追溯表\n")
            .nth(1)
            .and_then(|rest| rest.split("\n## 里程碑验收与回滚\n").next())
            .expect("the plan no longer has a traceability table");
        let mut rows = 0;
        let mut symbols = 0_usize;
        for line in table.lines() {
            if !line.starts_with("| ") || line.starts_with("| 任务 ") || line.starts_with("|---")
            {
                continue;
            }
            rows += 1;
            let mut rest = line;
            while let Some(at) = rest.find("src/") {
                rest = &rest[at..];
                let close = rest.find('`').unwrap_or(rest.len());
                let citation = &rest[..close];
                let looks_like_a_range = citation
                    .split_once("::")
                    .map_or_else(|| citation.split_once(':').map(|(_, spec)| spec), |_| None)
                    .is_some_and(|spec| {
                        !spec.is_empty()
                            && spec
                                .chars()
                                .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
                    });
                assert!(
                    !looks_like_a_range,
                    "the traceability table cites `{citation}`: a line range is true only until \
                     the next edit, so this table points at `src/<file>.rs::<symbol>` instead"
                );
                if citation.contains("::") {
                    symbols += 1;
                }
                rest = &rest[close..];
            }
        }
        assert_eq!(rows, 10, "the traceability table has {rows} rows");
        assert!(
            symbols >= 15,
            "only {symbols} rows of the traceability table point at a symbol: the scan is not \
             looking at the table"
        );
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

    /// The README says how each guest spells a backslash, and [`GuestPath`] does what it says.
    ///
    /// `join` used to fold `\` into `/` for every guest, which turned a Linux entry named
    /// `a\b` into `a/b` for the walk that drives `download`, `upload` and `remove_dir_all`.
    /// The rule is per guest, so the sentence and the behaviour have to be checked together:
    /// a phrase-only guard would pass on a README that describes code nobody has.
    #[test]
    fn the_readme_states_how_each_guest_spells_a_backslash() {
        use crate::guest_path::GuestPath;
        use crate::image::GuestOs;

        let linux = GuestPath::new(GuestOs::Linux, "/tmp/tree")
            .expect("a Linux path")
            .join("a\\b")
            .expect("a backslash is a legal character in a POSIX name");
        let windows = GuestPath::new(GuestOs::Windows, "C:/tree")
            .expect("a Windows path")
            .join("a\\b")
            .expect("Windows accepts both separators");

        assert_eq!(
            linux.as_str(),
            "/tmp/tree/a\\b",
            "a Linux guest path must keep a backslash as part of the name"
        );
        assert_eq!(
            windows.as_str(),
            "C:/tree/a/b",
            "a Windows guest path must treat a backslash as a separator"
        );

        // Locate the paragraph by what it says, not by the heading above it: renaming the
        // heading is not a change to this rule.
        const README: &str = include_str!("../README.md");
        let paragraph = README
            .split("\n\n")
            .find(|chunk| chunk.contains("Every remote path is converted to a guest path"))
            .expect("the README must still explain how a remote path becomes a guest path");
        let flat = paragraph.split_whitespace().collect::<Vec<_>>().join(" ");
        for claim in [
            "On a Windows guest both `/` and `\\` are accepted on input",
            "A Linux guest path keeps `\\` as an ordinary character in a name",
        ] {
            assert!(
                flat.contains(claim),
                "the README no longer states `{claim}`, which is what `GuestPath::join` now \
                 does for each guest"
            );
        }
    }

    /// A changelog entry is filed under the heading its own sentence describes.
    ///
    /// `### Added` is where a reader looks for a capability they did not have before; someone who
    /// upgrades and wants to know whether the hang they hit is gone reads `### Fixed`. Until R172
    /// nothing compared the two, and nine `[Unreleased]` bullets that narrate an old defect ("ran
    /// `xorriso` without a deadline", "was parsed as \"no expiry\"", "is now capped ...", "no longer
    /// requires ...") sat in the feature list. The rule here is mechanical - an `### Added` bullet
    /// may not narrate the past or the change - and two of the re-filed entries are read back from
    /// the code they describe, so deleting the sentence is not a way to comply.
    #[test]
    fn the_unreleased_changelog_files_each_entry_under_the_change_it_describes() {
        const CHANGELOG_TEXT: &str = include_str!("../CHANGELOG.md");
        let unreleased = CHANGELOG_TEXT
            .split("## [Unreleased]")
            .nth(1)
            .and_then(|rest| rest.split("\n## [").next())
            .expect("the changelog must still have an [Unreleased] section");
        let sections = changelog_sections(unreleased);
        let bullets_under = |wanted: &str| -> Vec<String> {
            sections
                .iter()
                .find(|(heading, _)| heading == wanted)
                .map(|(_, bullets)| bullets.clone())
                .unwrap_or_else(|| panic!("[Unreleased] has no `### {wanted}` section"))
        };

        let added = bullets_under("Added");
        assert!(
            added.len() >= 15,
            "the Added list shrank to {} entries, which is not this plan's feature set: {added:#?}",
            added.len()
        );
        for bullet in &added {
            let flat = format!(
                " {} ",
                bullet.split_whitespace().collect::<Vec<_>>().join(" ")
            );
            for marker in [
                " was ",
                " were ",
                " ran ",
                " carried ",
                " logged ",
                " no longer ",
                " is now ",
                " are now ",
                " silently ",
            ] {
                assert!(
                    !flat.contains(marker),
                    "an entry filed under `### Added` narrates a past defect or a change \
                     ({marker:?}), which belongs under `### Changed` or `### Fixed`: {bullet}"
                );
            }
        }

        // The re-filed entries are still stated, and still stated as fixes.
        let fixed = bullets_under("Fixed");
        let fixed_text = fixed
            .iter()
            .map(|bullet| bullet.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join("\n");
        for claim in [
            "without a deadline",
            "A lease that never expires",
            "30-space hole",
            "Symbolic links are no longer skipped silently",
        ] {
            assert!(
                fixed_text.contains(claim),
                "`### Fixed` no longer records `{claim}`, which R172 moved there from `### Added`"
            );
        }

        // Two of those sentences name code; the code has to still do what they say.
        assert!(
            crate::windows::SEED_BUILD_BUDGET > std::time::Duration::ZERO,
            "the seed ISO build still runs `xorriso` without a deadline"
        );
        let leases = crate::utils::parse_dhcp_leases(
            "infinite   52:54:00:aa:bb:cc   ipv4   192.168.221.42/24",
        );
        assert_eq!(
            leases.len(),
            1,
            "the lease row must still parse: {leases:#?}"
        );
        assert_eq!(
            leases[0].expiry, "infinite",
            "a lease that never expires is no longer read as `infinite`, so the entry under \
             `### Fixed` describes behaviour that does not exist"
        );
    }

    /// A path rule the user can observe is written in the README *and* in the changelog.
    ///
    /// R149 and R150 each changed what a user sees - a Linux guest keeps a backslash, and an
    /// entry without a UTF-8 spelling is refused - and each updated the README support matrix.
    /// Neither added a changelog entry, which is the same gap R140 recorded as F146: a reader of
    /// the release notes learns nothing about a behaviour that changed under them. The table below
    /// is deliberately short - it covers the two rules this plan added - and each row is checked
    /// against the README, the changelog and the code, so a reworded claim cannot pass alone.
    #[test]
    fn the_path_rules_a_user_can_observe_are_in_the_readme_and_the_changelog() {
        use crate::guest_path::GuestPath;
        use crate::image::GuestOs;

        const README_TEXT: &str = include_str!("../README.md");
        const CHANGELOG_TEXT: &str = include_str!("../CHANGELOG.md");

        let unreleased = CHANGELOG_TEXT
            .split("## [Unreleased]")
            .nth(1)
            .and_then(|rest| rest.split("\n## [").next())
            .expect("the changelog must still have an [Unreleased] section");
        let flat_changelog = unreleased.split_whitespace().collect::<Vec<_>>().join(" ");
        let flat_readme = README_TEXT.split_whitespace().collect::<Vec<_>>().join(" ");

        // Rule 1: a backslash separates only on Windows.
        assert_eq!(
            GuestPath::new(GuestOs::Linux, "/tmp/tree")
                .expect("a Linux path")
                .join("a\\b")
                .expect("a Linux name may contain a backslash")
                .as_str(),
            "/tmp/tree/a\\b",
            "a Linux guest path must keep a backslash as part of the name"
        );
        assert!(
            flat_readme
                .contains("A Linux guest path keeps `\\` as an ordinary character in a name"),
            "the README no longer states the Linux backslash rule"
        );
        assert!(
            flat_changelog.contains("a backslash separates only on Windows"),
            "the changelog no longer records that a backslash separates only on Windows"
        );

        // Rule 2: a name with no guest spelling is refused.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let unspellable = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"tree/f\xff"));
            assert!(
                crate::machine::guest_relative_path(&unspellable).is_err(),
                "a name that is not valid UTF-8 must be refused"
            );
        }
        assert!(
            flat_readme.contains("an entry whose name is not valid UTF-8 is refused by name"),
            "the README no longer states the non-UTF-8 refusal"
        );
        assert!(
            flat_changelog
                .contains("an entry whose name has no guest spelling is now refused by name"),
            "the changelog no longer records the non-UTF-8 refusal"
        );
    }

    /// A guest name that cannot be spelled is refused, not approximated.
    ///
    /// `to_string_lossy` is not a converter: it renders every non-UTF-8 byte as `U+FFFD`, so
    /// two entries that differ only in such a byte get one guest name and the second upload
    /// silently overwrites the first. The rule only holds if the README says it *and* the
    /// converter does it, so this guard reads both - a README paragraph describing code that
    /// no longer exists is exactly what a wording-only check would bless.
    #[test]
    fn the_readme_states_that_a_non_utf8_name_is_refused_and_the_upload_refuses_it() {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;

        #[cfg(unix)]
        let unspellable = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"tree/f\xff"));
        #[cfg(not(unix))]
        let unspellable = std::path::PathBuf::from("tree/f");
        let error = crate::machine::guest_relative_path(&unspellable)
            .expect_err("a name that is not valid UTF-8 has no guest spelling");
        assert!(
            error.to_string().contains("not valid UTF-8"),
            "the refusal must say why the entry cannot be uploaded: {error}"
        );
        #[cfg(unix)]
        {
            let colliding = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"tree/f\xfe"));
            assert!(
                crate::machine::guest_relative_path(&colliding).is_err(),
                "the entry that would have collided with the one above must also be refused"
            );
        }
        // The control: a valid UTF-8 name is accepted and kept, so the guard is not just
        // asserting that the function fails.
        assert_eq!(
            crate::machine::guest_relative_path(std::path::Path::new("tree/f\u{00ff}"))
                .expect("a valid UTF-8 name"),
            "tree/f\u{00ff}"
        );

        // The refusal must be on the path `upload` actually takes: the helper can be perfect
        // while the walk keeps rendering names lossily.
        const MACHINE: &str = include_str!("../src/machine.rs");
        let upload = function_body(MACHINE, "pub async fn upload<");
        assert!(
            !upload.contains("to_string_lossy"),
            "`Machine::upload` renders a walked entry lossily again"
        );
        assert!(
            upload.contains("guest_relative_path("),
            "`Machine::upload` no longer goes through `guest_relative_path`"
        );

        const README: &str = include_str!("../README.md");
        let row = README
            .split("\n\n")
            .flat_map(|chunk| chunk.lines())
            .find(|line| line.starts_with("| `upload` / `download` (file and directory)"))
            .expect("the README must still have the upload/download support row");
        let flat = row.split_whitespace().collect::<Vec<_>>().join(" ");
        for claim in [
            "an entry whose name is not valid UTF-8 is refused by name",
            "instead of being uploaded under `U+FFFD`",
        ] {
            assert!(
                flat.contains(claim),
                "the README no longer states `{claim}`, which is what `guest_relative_path` \
                 does for a name that cannot be spelled"
            );
        }
    }

    /// Each round's evidence reads the same in the plan and in the status view.
    ///
    /// Each round's summary is written twice - once in the revision history, once in the review
    /// log's row - and the status view's digest carries the newest round again. R148 exists
    /// because the two drifted: the plan's R147 row lost its negative results to a stray `cp`
    /// restore, and the commit message described evidence that was no longer in the tree.
    ///
    /// R152 is the same failure one level up: the guard R148 added only read the newest round,
    /// so one hundred and forty-seven rounds could disagree with themselves unnoticed. Both
    /// spellings of a tally are read now, and the guard refuses to report success on a scan that
    /// looked at only a handful of rounds.
    #[test]
    fn every_round_states_the_same_counts_in_both_documents() {
        const PLAN: &str = include_str!("../docs/plan/plan-20261104-windows-guest.md");
        const STATUS: &str = include_str!("../docs/plan/plan-status.md");

        let lines: Vec<&str> = PLAN.lines().collect();
        let log_at = lines
            .iter()
            .position(|line| line.trim_end() == "## Review log")
            .expect("the plan has no Review log section");

        let rounds = |row: &str| {
            row.strip_prefix("| R")
                .map(|rest| {
                    rest.chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                })
                .filter(|digits| !digits.is_empty())
                .and_then(|digits| digits.parse::<u32>().ok())
        };

        let mut compared = 0usize;
        let mut newest = 0u32;
        for line in &lines[log_at..] {
            let Some(round) = rounds(line) else {
                continue;
            };
            newest = newest.max(round);
            let heading = format!("review R{round}（");
            let Some(history) = lines.iter().find(|row| row.contains(&heading)) else {
                continue;
            };
            for (label, what) in [("变异", "mutations caught"), ("负结果", "negative results")]
            {
                let planned = spelled_tally(history, label);
                let logged = spelled_tally(line, label);
                match (planned, logged) {
                    (Some(planned), Some(logged)) => {
                        assert_eq!(
                            planned, logged,
                            "R{round} states {planned} {what} in the revision history and \
                             {logged} in the review log: the same round cannot have two tallies"
                        );
                        compared += 1;
                    }
                    (None, None) => {}
                    // Sixteen rows used to state a count in one document only, so the same
                    // evidence could be read as one number here and nothing there; R152 filled
                    // them in. A round that goes back to stating a count in one place only is a
                    // round whose evidence cannot be cross-checked, so it fails here.
                    (planned, logged) => panic!(
                        "R{round} states {what} in only one of the two documents \
                         (history: {planned:?}, log: {logged:?}): state the count in both, or the \
                         two views of this round cannot be compared"
                    ),
                }
            }
        }

        // The scan has to be wide enough to be worth anything: a silent change of shape would
        // otherwise turn this guard into a test of an empty set, which is how F160 hid.
        assert!(
            compared >= 70,
            "only {compared} tallies were compared in both documents; the guard is not reading \
             the tables it was written for. The floor is the number R152 measured - older \
             rounds describe their evidence in prose without a count at all, so this guard \
             speaks about the pairs that do count, and about every round from R148 on."
        );
        assert!(
            newest >= 150,
            "the newest round found is R{newest}: the scan is not reading the review log"
        );

        // The status view repeats the newest round, so it gets its own comparison.
        let digest = STATUS
            .lines()
            .find(|line| line.starts_with("| [`plan-20261104-windows-guest.md`]"))
            .expect("the status view no longer has a row for this plan");
        let start = digest
            .rfind(&format!("R{newest} "))
            .unwrap_or_else(|| panic!("the status digest never mentions R{newest}"));
        let sentence = &digest[start..];
        for (label, what) in [("变异", "mutations caught"), ("负结果", "negative results")] {
            let reported = tally(sentence, &format!("{label} "))
                .unwrap_or_else(|| panic!("the status digest states no {what} for R{newest}"));
            let newest_row = lines
                .iter()
                .find(|row| row.contains(&format!("review R{newest}（")))
                .expect("the newest round has no revision-history row of its own");
            let planned = spelled_tally(newest_row, label)
                .unwrap_or_else(|| panic!("the plan's R{newest} row states no {what}"));
            assert_eq!(
                planned, reported,
                "the plan's R{newest} row says {planned} {what} and the status view says \
                 {reported}: the same round cannot have two tallies"
            );
        }
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
