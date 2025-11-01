use crate::rtsp_client::RTSPClient;

use std::sync::Arc;
use std::time::Duration;

use futures::future::{AbortHandle, Abortable};
use futures::prelude::*;
use tokio::sync::Mutex;
use tokio::time::sleep;

use log::debug;

pub struct KeepaliveController {
    abort_handle: Option<AbortHandle>,
}

impl KeepaliveController {
    pub fn start(rtsp_client: Arc<Mutex<RTSPClient>>) -> KeepaliveController {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let future = run(rtsp_client).map(Result::unwrap);
        let future = Abortable::new(future, abort_registration).map(|_| {});

        tokio::spawn(future);

        KeepaliveController { abort_handle: Some(abort_handle) }
    }

    pub fn stop(&mut self) {
        if let Some(abort_handle) = self.abort_handle.take() {
            abort_handle.abort();
        }
    }
}

async fn run(rtsp_client: Arc<Mutex<RTSPClient>>) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        sleep(Duration::from_secs(5)).await;

        let mut client = rtsp_client.lock().await;
        debug!("sending keepalive packet");
        client.options(vec![]).await?;
    }
}
