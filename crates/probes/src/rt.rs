//! Timing-sensitive probes run on their own thread with a private current-thread runtime,
//! so a busy speed test can't delay their wakeups and inflate RTTs (section 9).

use std::future::Future;

use tokio::sync::oneshot;

/// Runs `make()`'s future to completion on a fresh thread and returns its output.
pub async fn on_dedicated_thread<F, Fut, T>(name: &str, make: F) -> anyhow::Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T>,
    T: Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    std::thread::Builder::new().name(name.to_string()).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
        match rt {
            Ok(rt) => {
                let _ = tx.send(Ok(rt.block_on(make())));
            }
            Err(e) => {
                let _ = tx.send(Err(anyhow::Error::from(e)));
            }
        }
    })?;
    rx.await.map_err(|_| anyhow::anyhow!("probe thread exited"))?
}
