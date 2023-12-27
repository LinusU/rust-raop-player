use crate::ntp::NtpTime;
use crate::rtp::{RtpHeader, RtpTimePacket};
use crate::serialization::{Deserializable, Serializable};

use std::time::Duration;

use async_executor::{Task, LocalExecutor};
use async_io::Timer;
use async_net::UdpSocket;
use futures::prelude::*;

use log::{error, debug};

pub struct TimingController {
    task: Option<Task<()>>,
}

impl TimingController {
    pub fn start(executor: &LocalExecutor, socket: UdpSocket) -> TimingController {
        let future = run(socket).map(|result| { result.unwrap(); });

        TimingController { task: Some(executor.spawn(future)) }
    }

    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.cancel().await;
        }
    }
}

async fn run(socket: UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    // FIXME: `connected` should come from the UdpSocket
    let mut connected = false;

    loop {
        let mut req = [0u8; RtpTimePacket::SIZE];
        let mut n: usize;

        if connected {
            n = socket.recv(&mut req).await?;
        } else {
            let (_n, client) = socket.recv_from(&mut req).await?;
            n = _n;
            debug!("NTP remote port: {}", client.port());
            socket.connect(client).await?;
            connected = true;
        }

        if n > 0 {
            let req = RtpTimePacket::deserialize(&mut req.as_ref())?;
            let rsp = RtpTimePacket {
                header: RtpHeader {
                    proto: req.header.proto,
                    type_: 0x53 | 0x80,
                    seq: req.header.seq,
                },
                dummy: 0,
                recv_time: NtpTime::now(),
                ref_time: req.send_time,
                send_time: NtpTime::now(),
            };

            n = socket.send(&rsp.as_bytes()).await?;

            if n != rsp.size() {
                error!("error responding to sync");
            }

            debug!("NTP sync: {} (ref {})", rsp.send_time, rsp.ref_time);
        }

        if n == 0 {
            error!("read, disconnected on the other end");
            Timer::after(Duration::from_millis(100)).await;
        }
    }
}
