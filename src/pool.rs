use std::collections::HashMap;

use anyhow::{Result, bail};
use tokio::sync::Mutex;

use crate::{Image, Machine, MachineConfig};

/// A pool operation that has already captured the machine it works on.
type PoolTask<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;

/// What `shutdown_all` should do with one machine.
///
/// Separated from the pool loop so the decision can be tested: the interesting case is a
/// probe that *failed*, which used to abort that machine's task before any shutdown was
/// attempted.
#[derive(Debug, PartialEq, Eq)]
enum ShutdownStep {
    /// The machine is up: ask the guest to power down.
    ShutDown,
    /// The machine is already down: nothing to do.
    Skip,
    /// Liveness could not be determined (hung or unreadable QMP socket): shut down anyway.
    ShutDownWithoutLiveness { reason: String },
}

/// Decide the shutdown step from the machine's liveness probe.
///
/// "Unknown" is not "stopped": a QMP socket that does not answer is what a *hung* QEMU
/// looks like, and that is exactly the machine that must still be shut down (or killed)
/// instead of being left running to be SIGKILLed when the pool is dropped.
fn shutdown_step(probe: Result<bool>) -> ShutdownStep {
    match probe {
        Ok(true) => ShutdownStep::ShutDown,
        Ok(false) => ShutdownStep::Skip,
        Err(error) => ShutdownStep::ShutDownWithoutLiveness {
            reason: format!("{error:#}"),
        },
    }
}

/// Run every pool operation to completion and report each failure by machine name.
///
/// The operations are deliberately not cancelled when one machine fails: dropping a start
/// future mid-launch leaves a QEMU process whose pid was never recorded on the machine, and
/// the next start would then rebuild the overlay under a live guest. One machine's failure
/// must not decide the fate of the others.
async fn run_all<'a>(tasks: impl Iterator<Item = (String, PoolTask<'a>)>) -> Result<()> {
    let labelled = tasks.map(|(name, task)| async move {
        match task.await {
            Ok(()) => Ok(()),
            // The label is added as a context layer instead of being formatted into a fresh
            // error, so the machine's name and the reason survive together. Formatting the
            // error rendered only its outermost context: a caller told `beta: failed to ask
            // the QMP socket whether the machine was running` never learned that the socket at
            // `/run/…/qmp.sock` refused the connection, which is the half that says what to
            // check.
            Err(error) => Err(error.context(name)),
        }
    });
    let errors = futures::future::join_all(labelled)
        .await
        .into_iter()
        .filter_map(|result| result.err())
        .collect::<Vec<_>>();

    match errors.is_empty() {
        true => Ok(()),
        false => {
            let message = errors
                .iter()
                // `{:#}` renders the whole chain, `{}` renders the outermost context only.
                .map(|error| format!("{error:#}"))
                .collect::<Vec<_>>()
                .join("; ");
            Err(anyhow::anyhow!("{message}"))
        }
    }
}

/// Pool to manage multiple virtual machines.
pub struct MachinePool {
    pool: HashMap<String, Mutex<Machine>>,
}

impl Default for MachinePool {
    fn default() -> Self {
        Self::new()
    }
}

impl MachinePool {
    /// Create a new, empty machine pool.
    pub fn new() -> Self {
        Self {
            pool: HashMap::new(),
        }
    }

    /// Add a new machine to the pool.
    pub async fn add(
        &mut self,
        name: impl AsRef<str>,
        image: &Image,
        config: &MachineConfig,
    ) -> Result<()> {
        let name = name.as_ref();
        if self.pool.contains_key(name) {
            bail!("Machine with name '{}' already exists in the pool", name);
        }
        let machine = Machine::new(image, config).await?;
        self.pool.insert(name.to_owned(), Mutex::new(machine));
        Ok(())
    }

    /// Get a mutable reference to a machine by name.
    pub async fn get(&self, name: &str) -> Option<tokio::sync::MutexGuard<'_, Machine>> {
        match self.pool.get(name) {
            Some(machine) => Some(machine.lock().await),
            None => None,
        }
    }

    /// Initialize all machines in the pool concurrently.
    ///
    /// A Windows machine that already completed its one-time deployment is spawned
    /// instead, because it cannot run `init` again.
    ///
    /// Every machine is attempted: a failure is reported by name and never cancels the
    /// other starts.
    pub async fn init_all(&mut self) -> Result<()> {
        let tasks = self.pool.iter().map(|(name, machine)| {
            let name = name.clone();
            let task: PoolTask<'_> = Box::pin(async move {
                let mut m = machine.lock().await;
                if !m.is_running().await? {
                    // A Windows guest deployed on a previous start must be spawned, not
                    // initialized: it has no deployment seed left and `init` rejects that.
                    if m.wants_init() {
                        m.init().await?;
                    } else {
                        m.spawn().await?;
                    }
                }
                Ok(())
            });
            (name, task)
        });

        run_all(tasks).await
    }

    /// Spawn all machines in the pool concurrently.
    ///
    /// A Windows machine whose one-time deployment has not run yet is initialized instead,
    /// because spawning it would boot a guest with no installed SSH key.
    ///
    /// Every machine is attempted: a failure is reported by name and never cancels the
    /// other starts.
    pub async fn spawn_all(&mut self) -> Result<()> {
        let tasks = self.pool.iter().map(|(name, machine)| {
            let name = name.clone();
            let task: PoolTask<'_> = Box::pin(async move {
                let mut m = machine.lock().await;
                if !m.is_running().await? {
                    // A Windows guest that never deployed has no installed SSH key yet, so a
                    // plain spawn would boot an unreachable guest. Run the deployment instead.
                    if m.needs_first_boot() {
                        m.init().await?;
                    } else {
                        m.spawn().await?;
                    }
                }
                Ok(())
            });
            (name, task)
        });

        run_all(tasks).await
    }

    /// Shutdown all machines in the pool concurrently.
    ///
    /// This method collects errors from all shutdown attempts and returns them together.
    /// A machine whose liveness cannot be probed is still shut down: hibernating or hung
    /// guests are the ones that most need the graceful path, and skipping them leaves QEMU to
    /// be SIGKILLed on drop.
    pub async fn shutdown_all(&mut self) -> Result<()> {
        let tasks = self.pool.iter().map(|(name, machine)| {
            let name = name.clone();
            let task: PoolTask<'_> = Box::pin(async move {
                let mut m = machine.lock().await;
                match shutdown_step(m.is_running().await) {
                    ShutdownStep::Skip => Ok(()),
                    ShutdownStep::ShutDown => m.shutdown().await,
                    ShutdownStep::ShutDownWithoutLiveness { reason } => {
                        tracing::warn!(
                            "shutting down anyway: whether this machine is running could not be \
                             determined ({reason})"
                        );
                        m.shutdown_if_started().await.map_err(|error| {
                            anyhow::anyhow!(
                                "liveness could not be determined ({reason}) and the shutdown \
                                 that was attempted anyway failed: {error}"
                            )
                        })
                    }
                }
            });
            (name, task)
        });

        run_all(tasks).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_task(name: &str) -> (String, PoolTask<'static>) {
        (name.to_string(), Box::pin(async { Ok(()) }))
    }

    fn failing_task(name: &str, reason: &str) -> (String, PoolTask<'static>) {
        let message = format!("{name}: {reason}");
        (
            name.to_string(),
            Box::pin(async move { Err(anyhow::anyhow!(message)) }),
        )
    }

    #[tokio::test]
    async fn test_run_all_keeps_the_cause_a_machine_failure_carried() {
        // A pool entry point answers with one message for the whole pool, so the message is the
        // only thing a caller can act on. `is_running`, `init` and `shutdown` all add context
        // layers (`failed to ask the QMP socket …` over `failed to connect to the QMP socket at
        // …`), and formatting the error without `#` printed the label and the outermost layer
        // only: the socket that refused the connection never reached the caller.
        let tasks: Vec<(String, PoolTask<'static>)> = vec![(
            "alpha".to_string(),
            Box::pin(async {
                Err(
                    anyhow::anyhow!("failed to connect to the QMP socket at /run/vm-1/qmp.sock")
                        .context("failed to ask the QMP socket whether the machine was running"),
                )
            }),
        )];

        let error = run_all(tasks.into_iter()).await.expect_err("a failure");
        let message = error.to_string();
        assert!(
            message.contains("alpha"),
            "the machine is unnamed: {message}"
        );
        assert!(
            message.contains("failed to ask the QMP socket"),
            "the context layer is missing: {message}"
        );
        assert!(
            message.contains("/run/vm-1/qmp.sock"),
            "the cause the caller has to act on is missing: {message}"
        );
    }

    #[tokio::test]
    async fn test_run_all_names_every_failure() {
        // Two of three machines fail: both must be reported, and the healthy one must not
        // appear as a failure.
        let tasks = vec![
            failing_task("alpha", "no firmware"),
            ok_task("beta"),
            failing_task("gamma", "no TPM"),
        ];
        let error = run_all(tasks.into_iter())
            .await
            .expect_err("failures")
            .to_string();
        assert!(error.contains("alpha: no firmware"), "{error}");
        assert!(error.contains("gamma: no TPM"), "{error}");
        assert!(!error.contains("beta"), "{error}");
    }

    #[tokio::test]
    async fn test_run_all_is_quiet_when_every_machine_succeeds() {
        let tasks = vec![ok_task("alpha"), ok_task("beta")];
        assert!(run_all(tasks.into_iter()).await.is_ok());
    }

    #[tokio::test]
    async fn test_run_all_runs_every_task_even_after_a_failure() {
        // A dropped start future would leave a QEMU process with no recorded pid, so every
        // task must still be driven to completion.
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = ran.clone();
        let tasks: Vec<(String, PoolTask<'static>)> = vec![
            failing_task("alpha", "boom"),
            (
                "beta".to_string(),
                Box::pin(async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }),
            ),
        ];
        assert!(run_all(tasks.into_iter()).await.is_err());
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn test_a_failed_liveness_probe_still_shuts_the_machine_down() {
        // The machine answered: power it down.
        assert_eq!(shutdown_step(Ok(true)), ShutdownStep::ShutDown);
        // The machine is already down: nothing to do.
        assert_eq!(shutdown_step(Ok(false)), ShutdownStep::Skip);

        // The probe failed: a hung or unreadable QMP socket is what a *live* QEMU looks like
        // from here, so "unknown" must not become "stopped". Reporting the error instead of
        // shutting down left a running guest to be SIGKILLed when the pool was dropped.
        let step = shutdown_step(Err(anyhow::anyhow!(
            "failed to connect to QMP socket /run/qlean/vm/qmp.sock: connection refused"
        )));
        match step {
            ShutdownStep::ShutDownWithoutLiveness { reason } => {
                assert!(reason.contains("connection refused"), "{reason}");
                assert!(reason.contains("QMP"), "{reason}");
            }
            other => panic!("a failed probe must still lead to a shutdown, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "needs a real qemu-system-x86_64 on PATH (DEP-02); run in the qlean-smoke container"]
    #[serial_test::serial]
    async fn test_a_live_qemu_without_a_control_socket_is_still_shut_down() {
        // The state a hung or half-torn-down launch leaves behind: QEMU is alive, the QMP
        // socket is gone. `is_running` refuses to answer there (starting a second QEMU would
        // fight this one for the disk), so the pre-fix `shutdown_all` returned that error and
        // left the process running until `Drop` SIGKILLed whatever was left.
        let mut child = std::process::Command::new("qemu-system-x86_64")
            .args(["-machine", "none", "-display", "none", "-nodefaults"])
            .spawn()
            .expect("qemu-system-x86_64 must be on PATH for this test");
        let pid = child.id();

        let mut pool = MachinePool::new();
        pool.pool.insert(
            "hung".to_string(),
            Mutex::new(Machine::for_tests_with_pid(Some(pid))),
        );

        let outcome = pool.shutdown_all().await;
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        if !exited {
            let _ = child.kill();
        }
        let _ = child.wait();

        outcome
            .expect("a machine that is still running must be shut down, not reported as unknown");
        assert!(
            exited,
            "the live QEMU process {pid} was left running instead of being shut down"
        );
    }

    /// Each pool entry point asks its own question, and asking the other one is the bug.
    ///
    /// `init_all` must use `wants_init` (a deployed Windows guest is spawned) and `spawn_all`
    /// must use `needs_first_boot` (a pending one is deployed). The two predicates differ by
    /// one call and both live on `Machine`, so a copy-paste between the two branches would
    /// read as correct while sending one of the two cases down the wrong path.
    #[test]
    fn each_pool_entry_point_asks_its_own_question() {
        let source = include_str!("pool.rs");
        let body_of = |name: &str| -> &str {
            let start = source
                .find(&format!("pub async fn {name}"))
                .unwrap_or_else(|| panic!("`{name}` is gone from the pool"));
            let rest = &source[start..];
            let end = rest
                .find("\n    }\n")
                .unwrap_or_else(|| panic!("`{name}` has no closing brace"));
            &rest[..end]
        };

        let init_all = body_of("init_all");
        let spawn_all = body_of("spawn_all");
        assert!(
            init_all.contains(".wants_init()") && !init_all.contains(".needs_first_boot()"),
            "`init_all` must route through `wants_init`"
        );
        assert!(
            spawn_all.contains(".needs_first_boot()") && !spawn_all.contains(".wants_init()"),
            "`spawn_all` must route through `needs_first_boot`"
        );
    }

    #[tokio::test]
    async fn test_a_pool_of_machines_that_never_started_shuts_down_cleanly() {
        // A launch that died before its QMP socket appeared leaves exactly this: a machine
        // with nothing running. Its liveness probe fails, and folding that failure into
        // "shutdown failed" reported an error for a pool that was already fully down.
        let mut pool = MachinePool::new();
        pool.pool.insert(
            "ghost".to_string(),
            Mutex::new(Machine::never_started_for_tests()),
        );

        pool.shutdown_all()
            .await
            .expect("nothing is running, so no shutdown can fail");
    }
}
