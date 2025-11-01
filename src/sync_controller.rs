use crate::frames::Frames;
use crate::raop_client::{Sane, Status, MAX_BACKLOG};
use crate::rtp::{RtpAudioRetransmissionPacket, RtpLostPacket, RtpSyncPacket};
use crate::sample_rate::SampleRate;
use crate::serialization::{Deserializable, Serializable};

use std::sync::Arc;
use std::time::Duration;

use beefeater::{AddAssign, Beefeater};
use futures::future::{join, AbortHandle, Abortable};
use futures::prelude::*;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::sleep;

use log::{debug, error, info, trace, warn};

pub struct SyncController {
    abort_handle: Option<AbortHandle>,
    socket: Arc<UdpSocket>,
}

impl SyncController {
    pub fn start(socket: UdpSocket, status_mutex: Arc<Mutex<Status>>, sane_mutex: Arc<Mutex<Sane>>, retransmit: Arc<Beefeater<u32>>, latency: Frames, sample_rate: SampleRate) -> SyncController {
        let socket = Arc::new(socket);
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let receiving = receive(Arc::clone(&socket), Arc::clone(&status_mutex), sane_mutex, retransmit);
        let sending = send_sync_every_second(Arc::clone(&socket), status_mutex, latency, sample_rate);

        let pair = join(
            receiving.map(|result| {
                result.unwrap();
            }),
            sending.map(|result| {
                result.unwrap();
            }),
        );
        let future = Abortable::new(pair, abort_registration).map(|_| {});

        tokio::spawn(future);

        SyncController {
            abort_handle: Some(abort_handle),
            socket,
        }
    }

    pub fn stop(&mut self) {
        if let Some(abort_handle) = self.abort_handle.take() {
            abort_handle.abort();
        }
    }

    pub fn send_sync(&self, status: &mut Status, sample_rate: SampleRate, latency: Frames, first: bool) -> impl std::future::Future<Output = Result<(), std::io::Error>> {
        send_sync_paket(Arc::clone(&self.socket), RtpSyncPacket::build(status.head_ts, sample_rate, latency, first))
    }
}

async fn send_sync_paket(socket: Arc<UdpSocket>, rsp: RtpSyncPacket) -> Result<(), std::io::Error> {
    let n = socket.send(&rsp.as_bytes()).await?;

    debug!("sync ntp:{} (ts:{})", rsp.curr_time, rsp.rtp_timestamp);
    if n == 0 {
        info!("write, disconnected on the other end");
    }

    Ok(())
}

async fn receive(socket: Arc<UdpSocket>, status_mutex: Arc<Mutex<Status>>, sane_mutex: Arc<Mutex<Sane>>, retransmit: Arc<Beefeater<u32>>) -> Result<(), std::io::Error> {
    // Reuse this memory for receiving packet
    let mut buffer = [0u8; RtpLostPacket::SIZE];

    loop {
        let n = socket.recv(&mut buffer).await?;

        let lost = RtpLostPacket::deserialize(&mut buffer.as_ref());

        let lost = {
            let mut sane = sane_mutex.lock().await;

            match lost {
                Err(err) => {
                    error!("error in received request err:{} (recv:{})", err, n);
                    sane.ctrl += 1;
                    continue;
                }
                Ok(lost) => {
                    sane.ctrl = 0;
                    lost
                }
            }
        };

        let mut missed: i32 = 0;
        if lost.n > 0 {
            let status = status_mutex.lock().await;

            for i in 0..lost.n {
                let index = ((lost.seq_number + i) % MAX_BACKLOG) as usize;

                if status.backlog[index].as_ref().map(|e| e.seq_number).unwrap_or(0) == lost.seq_number + i {
                    if let Some(ref entry) = status.backlog[index] {
                        retransmit.add_assign(1);
                        socket.send(&RtpAudioRetransmissionPacket::wrap(&entry.packet).as_bytes()).await.unwrap();
                    } else {
                        // packet have been released meanwhile, be extra cautious
                        missed += 1;
                    }
                } else {
                    warn!("lost packet out of backlog {}", lost.seq_number + i);
                }
            }
        }

        debug!("retransmit packet sn:{} nb:{} (mis:{})", lost.seq_number, lost.n, missed);
    }
}

async fn send_sync_every_second(socket: Arc<UdpSocket>, status_mutex: Arc<Mutex<Status>>, latency: Frames, sample_rate: SampleRate) -> Result<(), std::io::Error> {
    loop {
        trace!("[SyncController::send_sync_every_second] - aquiring status");
        let status = status_mutex.lock().await;
        trace!("[SyncController::send_sync_every_second] - got status");

        let rsp = RtpSyncPacket::build(status.head_ts, sample_rate, latency, false);
        send_sync_paket(Arc::clone(&socket), rsp).await?;

        trace!("[SyncController::send_sync_every_second] - dropping status");
        drop(status);

        sleep(Duration::from_secs(1)).await;
    }
}
