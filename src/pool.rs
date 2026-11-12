use std::collections::HashMap;

use anyhow::{Result, bail};
use tokio::sync::Mutex;

use crate::{Image, Machine, MachineConfig};

/// A pool operation that has already captured the machine it works on.
type PoolTask<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;

/// Run every pool operation to completion and report each failure by machine name.
///
/// The operations are deliberately not cancelled when one machine fails: dropping a start
/// future mid-launch leaves a QEMU process whose pid was never recorded on the machine, and
/// the next start would then rebuild the overlay under a live guest. One machine's failure
/// must not decide the fate of the others.
async fn run_all<'a>(tasks: impl Iterator<Item = (String, PoolTask<'a>)>) -> Result<()> {
    let labelled = tasks
        .map(|(name, task)| async move { task.await.map_err(|e| anyhow::anyhow!("{name}: {e}")) });
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
                .map(|error| error.to_string())
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
    pub async fn shutdown_all(&mut self) -> Result<()> {
        let tasks = self.pool.iter().map(|(name, machine)| {
            let name = name.clone();
            let task: PoolTask<'_> = Box::pin(async move {
                let mut m = machine.lock().await;
                if m.is_running().await? {
                    m.shutdown().await?;
                }
                Ok(())
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
}
