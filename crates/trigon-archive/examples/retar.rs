//! Read a tar from argv[1], re-serialize it with our writer, write to argv[2].
//! Used to check our output against real tar implementations.
use std::sync::Arc;
use trigon_archive::{Limits, SourceMap, tar};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (inp, outp) = (args.next().unwrap(), args.next().unwrap());
    let bytes = std::fs::read(&inp)?;
    let mut notes = Vec::new();
    let mut a = tar::read(
        Arc::new(SourceMap::owned(bytes)),
        &Limits::default(),
        &mut notes,
    )?;
    a.sort_entries();
    let mut out = Vec::new();
    tar::write(&a, &mut out)?;
    std::fs::write(&outp, &out)?;
    for n in &notes {
        eprintln!(
            "note: {:?} {} {}",
            n.code,
            n.path
                .as_ref()
                .map(|p| p.to_lossy().into_owned())
                .unwrap_or_default(),
            n.detail
        );
    }
    Ok(())
}
