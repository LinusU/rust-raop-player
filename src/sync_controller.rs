use crate::frames::Frames;
use crate::raop_client::{MAX_BACKLOG, Sane, Status};
use crate::rtp::{RtpAudioRetransmissionPacket, RtpLostPacket, RtpSyncPacket};
use crate::sample_rate::SampleRate;
use crate::serialization::{Deserializable, Serializable};

use std::sync::Arc;
use std::time::Duration;

use async_executor::{Task, LocalExecutor};
use async_io::Timer;
use async_lock::Mutex;
use async_net::UdpSocket;
use beefeater::{AddAssign, Beefeater};
use futures_lite::future::zip;

use log::{error, warn, info, debug, trace};

pub struct SyncController {
    socket: Arc<UdpSocket>,
    task: Option<Task<(Result<(), std::io::Error>, Result<(), std::io::Error>)>>,
}

impl SyncController {
    pub fn start(executor: &LocalExecutor, socket: UdpSocket, status_mutex: Arc<Mutex<Status>>, sane_mutex: Arc<Mutex<Sane>>, retransmit: Arc<Beefeater<u32>>, latency: Frames, sample_rate: SampleRate) -> SyncController {
        let socket = Arc::new(socket);

        let receiving = receive(Arc::clone(&socket), Arc::clone(&status_mutex), sane_mutex, retransmit);
        let sending = send_sync_every_second(Arc::clone(&socket), status_mutex, latency, sample_rate);

        SyncController { socket, task: Some(executor.spawn(zip(receiving, sending))) }
    }

    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.cancel().await;
        }
    }

    pub fn send_sync(&self, status: &mut Status, sample_rate: SampleRate, latency: Frames, first: bool) -> impl std::future::Future<Output = Result<(), std::io::Error>> {
        send_sync_paket(Arc::clone(&self.socket), RtpSyncPacket::build(status.head_ts, sample_rate, latency, first))
    }
}

async fn send_sync_paket(socket: Arc<UdpSocket>, rsp: RtpSyncPacket) -> Result<(), std::io::Error> {
    let n = socket.send(&rsp.as_bytes()).await?;

    debug!("sync ntp:{} (ts:{})", rsp.curr_time, rsp.rtp_timestamp);
    if n == 0 { info!("write, disconnected on the other end"); }

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

        Timer::after(Duration::from_secs(1)).await;
    }
}
