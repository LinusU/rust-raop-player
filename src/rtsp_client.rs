use crate::bindings::{rtspcl_s, rtspcl_create, rtspcl_connect, rtspcl_disconnect, rtspcl_pair_verify, rtspcl_auth_setup, rtspcl_announce_sdp, rtspcl_setup, rtspcl_record, rtspcl_set_parameter, rtspcl_flush, rtspcl_remove_all_exthds, rtspcl_add_exthds, rtspcl_mark_del_exthds, rtspcl_local_ip, rtspcl_destroy, rtp_port_s, key_data_t};

use std::ffi::{CStr, CString};

use std::net::Ipv4Addr;

pub struct RTSPClient {
    c_handle: *mut rtspcl_s,
}

impl RTSPClient {
    pub fn new(user_agent: &str) -> Option<RTSPClient> {
        let c_handle = unsafe { rtspcl_create(CString::new(user_agent).unwrap().into_raw()) };
        if c_handle.is_null() { None } else { Some(RTSPClient { c_handle }) }
    }

    // bool rtspcl_set_useragent(struct rtspcl_s *p, const char *name);

    pub fn connect(&self, local: Ipv4Addr, host: Ipv4Addr, destport: u16, sid: &str) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_connect(self.c_handle, local.into(), host.into(), destport, CString::new(sid).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to connect") }
    }

    pub fn disconnect(&self) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_disconnect(self.c_handle) };
        if success { Ok(()) } else { panic!("Failed to disconnect") }
    }

    // bool rtspcl_is_connected(struct rtspcl_s *p);
    // bool rtspcl_is_sane(struct rtspcl_s *p);
    // bool rtspcl_options(struct rtspcl_s *p, key_data_t *rkd);

    pub fn pair_verify(&self, secret: &str) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_pair_verify(self.c_handle, CString::new(secret).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to pair verify") }
    }

    pub fn auth_setup(&self) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_auth_setup(self.c_handle) };
        if success { Ok(()) } else { panic!("Failed to setup auth") }
    }

    pub fn announce_sdp(&self, sdp: &str) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_announce_sdp(self.c_handle, CString::new(sdp).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to announce sdp") }
    }

    pub fn setup(&self, port: &mut rtp_port_s, kd: &mut [key_data_t]) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_setup(self.c_handle, port, &mut kd[0]) };
        if success { Ok(()) } else { panic!("Failed to setup") }
    }

    pub fn record(&self, start_seq: u16, start_ts: u32, kd: &mut [key_data_t]) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_record(self.c_handle, start_seq, start_ts, &mut kd[0]) };
        if success { Ok(()) } else { panic!("Failed to record") }
    }

    pub fn set_parameter(&self, param: &str) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_set_parameter(self.c_handle, CString::new(param).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to set parameter") }
    }

    pub fn flush(&self, seq_number: u16, timestamp: u32) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_flush(self.c_handle, seq_number, timestamp) };
        if success { Ok(()) } else { panic!("Failed to flush") }
    }

    // bool rtspcl_set_daap(struct rtspcl_s *p, u32_t timestamp, int count, va_list args);
    // bool rtspcl_set_artwork(struct rtspcl_s *p, u32_t timestamp, char *content_type, int size, char *image);

    pub fn remove_all_exthds(&self) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_remove_all_exthds(self.c_handle) };
        if success { Ok(()) } else { panic!("Failed to remove all exthds") }
    }

    pub fn add_exthds(&self, key: &str, data: &str) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_add_exthds(self.c_handle, CString::new(key).unwrap().into_raw(), CString::new(data).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to add exthds") }
    }

    pub fn mark_del_exthds(&self, key: &str) -> Result<(), Box<std::error::Error>> {
        let success = unsafe { rtspcl_mark_del_exthds(self.c_handle, CString::new(key).unwrap().into_raw()) };
        if success { Ok(()) } else { panic!("Failed to del exthds") }
    }

    pub fn local_ip(&self) -> Result<String, Box<std::error::Error>> {
        Ok(unsafe { CStr::from_ptr(rtspcl_local_ip(self.c_handle)).to_str()?.to_owned() })
    }
}

impl Drop for RTSPClient {
    fn drop(&mut self) {
        unsafe { rtspcl_destroy(self.c_handle); }
    }
}
