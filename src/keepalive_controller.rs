use crate::rtsp_client::RTSPClient;

use std::sync::Arc;
use std::time::Duration;

use async_executor::{Task, LocalExecutor};
use async_io::Timer;
use async_lock::Mutex;
use futures::prelude::*;

use log::debug;

pub struct KeepaliveController {
    task: Option<Task<()>>,
}

impl KeepaliveController {
    pub fn start(executor: &LocalExecutor, rtsp_client: Arc<Mutex<RTSPClient>>) -> KeepaliveController {
        let future = run(rtsp_client).map(|result| { result.unwrap(); });

        KeepaliveController { task: Some(executor.spawn(future))  }
    }

    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.cancel().await;
        }
    }
}

async fn run(rtsp_client: Arc<Mutex<RTSPClient>>) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        Timer::after(Duration::from_secs(5)).await;

        let mut client = rtsp_client.lock().await;
        debug!("sending keepalive packet");
        client.options(vec![]).await?;
    }
}
