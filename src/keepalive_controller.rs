use crate::rtsp_client::RTSPClient;

use std::sync::{Arc};

use futures::future::{Abortable, AbortHandle};
use futures::prelude::*;
use tokio::sync::Mutex;

use log::{info};

pub struct KeepaliveController {
    abort_handle: Option<AbortHandle>,
}

impl KeepaliveController {
    pub fn start(rtsp_client: Arc<Mutex<RTSPClient>>) -> KeepaliveController {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let future = run(rtsp_client).map(|result| { result.unwrap(); });
        let future = Abortable::new(future, abort_registration).map(|_| {});

        tokio::runtime::current_thread::spawn(future);

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
        tokio::timer::delay_for(std::time::Duration::from_secs(30)).await;

        let mut client = rtsp_client.lock().await;
        info!("sending keepalive packet");
        client.options(vec![]).await?;
    }
}
