use std::fmt::Debug;
use std::ops::{Add, Sub};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SuspendAwareInstant(Duration);

impl SuspendAwareInstant {
    pub(crate) fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    pub(crate) fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.0.checked_sub(duration).map(Self)
    }

    pub(crate) fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    #[cfg(test)]
    pub(crate) fn now() -> Self {
        system_suspend_aware_now().expect("suspend-aware test clock must be available")
    }
}

impl Add<Duration> for SuspendAwareInstant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        self.checked_add(rhs)
            .expect("suspend-aware instant addition overflowed")
    }
}

impl Sub<Duration> for SuspendAwareInstant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        self.checked_sub(rhs)
            .expect("suspend-aware instant subtraction underflowed")
    }
}

pub(crate) trait SuspendAwareClock: Debug + Send + Sync {
    fn now(&self) -> Option<SuspendAwareInstant>;
}

#[derive(Debug, Default)]
pub(crate) struct SystemSuspendAwareClock;

impl SuspendAwareClock for SystemSuspendAwareClock {
    fn now(&self) -> Option<SuspendAwareInstant> {
        system_suspend_aware_now()
    }
}

#[cfg(target_os = "linux")]
fn system_suspend_aware_now() -> Option<SuspendAwareInstant> {
    // Unlike CLOCK_MONOTONIC, CLOCK_BOOTTIME includes time spent suspended.
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } != 0 {
        return None;
    }
    let value = unsafe { value.assume_init() };
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return None;
    }

    Some(SuspendAwareInstant(Duration::new(
        value.tv_sec as u64,
        value.tv_nsec as u32,
    )))
}

#[cfg(target_os = "macos")]
fn system_suspend_aware_now() -> Option<SuspendAwareInstant> {
    use std::sync::OnceLock;

    #[repr(C)]
    struct MachTimebaseInfo {
        numerator: u32,
        denominator: u32,
    }

    // mach_continuous_time advances while the machine is asleep.
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
    }

    static TIMEBASE: OnceLock<Option<(u32, u32)>> = OnceLock::new();
    let &(numerator, denominator) = TIMEBASE
        .get_or_init(|| {
            let mut info = std::mem::MaybeUninit::<MachTimebaseInfo>::uninit();
            if unsafe { mach_timebase_info(info.as_mut_ptr()) } != 0 {
                return None;
            }
            let info = unsafe { info.assume_init() };
            (info.denominator != 0).then_some((info.numerator, info.denominator))
        })
        .as_ref()?;
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks)
        .checked_mul(u128::from(numerator))?
        .checked_div(u128::from(denominator))?;
    let seconds = u64::try_from(nanos / 1_000_000_000).ok()?;
    let subsecond_nanos = u32::try_from(nanos % 1_000_000_000).ok()?;

    Some(SuspendAwareInstant(Duration::new(seconds, subsecond_nanos)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn system_suspend_aware_now() -> Option<SuspendAwareInstant> {
    None
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct TestSuspendAwareClock {
    nanos: std::sync::atomic::AtomicU64,
    available: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl TestSuspendAwareClock {
    pub(crate) fn new(now: Duration) -> Self {
        Self {
            nanos: std::sync::atomic::AtomicU64::new(
                now.as_nanos()
                    .try_into()
                    .expect("test clock value must fit in u64 nanoseconds"),
            ),
            available: std::sync::atomic::AtomicBool::new(true),
        }
    }

    pub(crate) fn advance(&self, duration: Duration) {
        self.nanos.fetch_add(
            duration
                .as_nanos()
                .try_into()
                .expect("test clock advance must fit in u64 nanoseconds"),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub(crate) fn fail(&self) {
        self.available
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
impl SuspendAwareClock for TestSuspendAwareClock {
    fn now(&self) -> Option<SuspendAwareInstant> {
        if !self.available.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        Some(SuspendAwareInstant(Duration::from_nanos(
            self.nanos.load(std::sync::atomic::Ordering::Relaxed),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{SuspendAwareClock, SystemSuspendAwareClock};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn system_clock_is_available_and_advances() {
        let clock = SystemSuspendAwareClock;
        let before = clock.now().unwrap();
        let after = clock.now().unwrap();

        assert!(after >= before);
    }
}
