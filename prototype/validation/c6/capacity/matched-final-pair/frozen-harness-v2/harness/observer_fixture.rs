//! Bounded measurement-only macOS observer; no Tokio task or per-event allocation.
use std::{fs::OpenOptions, io::{BufWriter, Write}, path::Path,
    sync::{OnceLock, Mutex, mpsc::{self, SyncSender}, atomic::{AtomicU64, Ordering}},
    thread::JoinHandle};
static SENDER: OnceLock<Mutex<Option<SyncSender<[u8;96]>>>> = OnceLock::new();
static EMITTED: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static INVALID: AtomicU64 = AtomicU64::new(0);
static WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);
unsafe extern "C" { fn mach_absolute_time() -> u64; }
fn commit(delivery: &str, device: &str, attempt: i64, state: &str) {
    // SAFETY: zero-argument system monotonic clock, no pointers or ownership.
    let ticks = unsafe { mach_absolute_time() };
    let state = match state { "provider_accepted"=>1, "permanent_failed"=>2,
        "expired"=>3, "cancelled"=>4, "retry_wait"=>5, _=>0 };
    if delivery.len()!=32 || device.len()!=32 || !delivery.is_ascii()
        || !device.is_ascii() || attempt<0 || state==0 {
        INVALID.fetch_add(1,Ordering::Relaxed); return;
    }
    let sequence = EMITTED.fetch_add(1,Ordering::Relaxed);
    let mut record=[0_u8;96];
    record[0..8].copy_from_slice(&ticks.to_le_bytes());
    record[8..16].copy_from_slice(&(attempt as u64).to_le_bytes());
    record[16..24].copy_from_slice(&sequence.to_le_bytes());
    record[24..56].copy_from_slice(delivery.as_bytes());
    record[56..88].copy_from_slice(device.as_bytes()); record[88]=state;
    // try_lock plus try_send: observer cannot wait behind a consumer or shutdown.
    let sent = SENDER.get().and_then(|s| s.try_lock().ok())
        .and_then(|s| s.as_ref().map(|tx| tx.try_send(record).is_ok())).unwrap_or(false);
    if !sent { DROPPED.fetch_add(1,Ordering::Relaxed); }
}
pub struct Session { writer: JoinHandle<()>, summary: std::path::PathBuf }
impl Session {
    pub fn start(path: &Path) -> Result<Self,Box<dyn std::error::Error>> {
        let file=OpenOptions::new().write(true).create_new(true).open(path)?;
        let (tx,rx)=mpsc::sync_channel::<[u8;96]>(4096);
        SENDER.set(Mutex::new(Some(tx))).map_err(|_| "observer already installed")?;
        let writer=std::thread::spawn(move || {
            let mut out=BufWriter::with_capacity(64*1024,file);
            let mut failed=false;
            for record in rx {
                if !failed && out.write_all(&record).is_err() {
                    WRITE_ERRORS.fetch_add(1,Ordering::Relaxed); failed=true;
                }
            }
            if !failed && out.flush().is_err() { WRITE_ERRORS.fetch_add(1,Ordering::Relaxed); }
        });
        free_delivery_prototype::commit_observer::install(commit).map_err(|_| "callback already installed")?;
        Ok(Self{writer,summary:path.with_extension("observer.json")})
    }
    pub fn finish(self) -> Result<(),Box<dyn std::error::Error>> {
        SENDER.get().unwrap().lock().unwrap().take();
        let joined=self.writer.join().is_ok();
        let dropped=DROPPED.load(Ordering::Relaxed);
        let invalid=INVALID.load(Ordering::Relaxed);
        let errors=WRITE_ERRORS.load(Ordering::Relaxed);
        let summary=serde_json::json!({"writer_joined":joined,"emitted":EMITTED.load(Ordering::Relaxed),
            "dropped":dropped,"invalid_ids":invalid,"write_errors":errors,
            "capacity_records":4096,"record_bytes":96,"writer_buffer_bytes":65536,
            "clock":"mach_absolute_time","boundary":"successful receipt COMMIT await returned, changed target only"});
        let mut file=OpenOptions::new().write(true).create_new(true).open(self.summary)?;
        writeln!(file,"{summary}")?;
        if !joined || dropped!=0 || invalid!=0 || errors!=0 { return Err("invalid commit telemetry".into()); }
        Ok(())
    }
}
