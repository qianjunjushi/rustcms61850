use std::future::Future;
use tokio::sync::broadcast;
 

pub async fn slow_shutdown(
    shutdownch: broadcast::Sender<()>,
    shutdown: impl Future,
) -> crate::Result<()> {
    tokio::select! {
        _ = shutdown  => {
            // The shutdown signal has been received.
            shutdownch.send(())?;
            drop(shutdownch);
            println!("shutting down total");
        }
    }
    Ok(())
}
