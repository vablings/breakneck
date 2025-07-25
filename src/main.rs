use dll_syringe::{process::OwnedProcess, Syringe};

use std::{
    io::{Read, Write},
    net::TcpListener,
};
use tracing::metadata::LevelFilter;

fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::INFO)
        .init();

    let listener = TcpListener::bind("127.0.0.1:7331")?;

    log::info!("Starting debug console...");

    let proc = OwnedProcess::find_first_by_name("helloworldtesting").unwrap();
    //let proc = OwnedProcess::from_pid(13112).unwrap();
    let syringe = Syringe::for_process(proc);
    //let injected_payload = syringe.inject(r"C:\Users\vc\Desktop\not-byfron\x64\Debug\not-byfron.dll").unwrap();
    let injected_payload = syringe.inject("./target/debug/inject_me.dll").unwrap();

    let (mut stream, address) = listener.accept()?;
    log::info!("{address} has connected");
    let mut buf = vec![0u8; 1024];
    let mut stdout = std::io::stdout();
    while let Ok(n) = stream.read(&mut buf[..]) {
        stdout.write_all(&buf[..n])?;
    }
    Ok(())
}
