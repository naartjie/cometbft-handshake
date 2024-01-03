use std::error::Error;
use tokio::net::TcpStream;

use cometbft_handshake::handshake;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    let addr = "127.0.0.1:26656";
    let stream = TcpStream::connect(addr).await?;
    println!("connection to peer opened on {}", addr);

    handshake::do_handshake(stream).await?;
    Ok(())
}
