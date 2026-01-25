use std::collections::HashMap;

use anyhow::{Result, bail};
use tokio::sync::Mutex;

use crate::{Image, Machine, MachineConfig};

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
    pub async fn add(&mut self, name: String, image: &Image, config: &MachineConfig) -> Result<()> {
        if self.pool.contains_key(&name) {
            bail!("Machine with name '{}' already exists in the pool", name);
        }
        let machine = Machine::new(image, config).await?;
        self.pool.insert(name, Mutex::new(machine));
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
    /// This is a short-circuiting method: execution returns immediately upon encountering the first machine initialization error, discarding any remaining tasks.
    pub async fn init_all(&mut self) -> Result<()> {
        let tasks = self.pool.values().map(|machine| async {
            let mut m = machine.lock().await;
            if !m.is_running().await? {
                m.init().await?;
            }
            Ok::<(), anyhow::Error>(())
        });

        futures::future::try_join_all(tasks).await?;
        Ok(())
    }

    /// Spawn all machines in the pool concurrently.
    ///
    /// This is a short-circuiting method: execution returns immediately upon encountering the first machine spawn error, discarding any remaining tasks.
    pub async fn spawn_all(&mut self) -> Result<()> {
        let tasks = self.pool.values().map(|machine| async {
            let mut m = machine.lock().await;
            if !m.is_running().await? {
                m.spawn().await?;
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
