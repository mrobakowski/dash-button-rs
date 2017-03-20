use std::time::Duration;

pub trait DurationExt {
    fn from_timeval(v: ::libc::timeval) -> Duration {
        Duration::from_secs(v.tv_sec as u64) + Duration::new(0, v.tv_usec as u32 * 1000)
    }
}

impl DurationExt for Duration {}
