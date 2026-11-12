use std::collections::HashMap;

use anyhow::{Result, bail};
use tokio::sync::Mutex;

use crate::{Image, Machine, MachineConfig};

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
    /// This is a short-circuiting method: execution returns immediately upon encountering the first machine initialization error, discarding any remaining tasks.
    pub async fn init_all(&mut self) -> Result<()> {
        let tasks = self.pool.values().map(|machine| async {
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
            Ok::<(), anyhow::Error>(())
        });

        futures::future::try_join_all(tasks).await?;
        Ok(())
    }

    /// Spawn all machines in the pool concurrently.
    ///
    /// A Windows machine whose one-time deployment has not run yet is initialized instead,
    /// because spawning it would boot a guest with no installed SSH key.
    ///
    /// This is a short-circuiting method: execution returns immediately upon encountering the first machine spawn error, discarding any remaining tasks.
    pub async fn spawn_all(&mut self) -> Result<()> {
        let tasks = self.pool.values().map(|machine| async {
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
            Ok::<(), anyhow::Error>(())
        });

        futures::future::try_join_all(tasks).await?;
        Ok(())
    }

    /// Shutdown all machines in the pool concurrently.
    ///
    /// This method collects errors from all shutdown attempts and returns them together.
    pub async fn shutdown_all(&mut self) -> Result<()> {
        let tasks = self.pool.iter().map(|(name, machine)| {
            let name = name.clone();
            async move {
                let result = async {
                    let mut m = machine.lock().await;
                    if m.is_running().await? {
                        m.shutdown().await?;
                    }
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                result.map_err(|e| anyhow::anyhow!("{}: {}", name, e))
            }
        });

        let results: Vec<Result<(), anyhow::Error>> = futures::future::join_all(tasks).await;
        let errors: Vec<anyhow::Error> = results.into_iter().filter_map(|r| r.err()).collect();

        if errors.is_empty() {
            Ok(())
        } else {
            let msg = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            Err(anyhow::anyhow!("shutdown errors: {}", msg))
        }
    }
}
