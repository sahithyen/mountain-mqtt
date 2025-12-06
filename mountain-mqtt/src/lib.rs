#![cfg_attr(not(feature = "std"), no_std)]

pub mod client;
pub mod client_state;
pub mod codec;
pub mod data;
pub mod error;
pub mod mqtt_manager;
pub mod packet_client;
pub mod packets;

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "embedded-io-async")]
pub mod embedded_io_async;

#[cfg(feature = "embedded-hal-async")]
pub mod embedded_hal_async;

#[cfg(feature = "embedded-io-async")]
impl<
        'a,
        C: ::embedded_io_async::Read + ::embedded_io_async::Write + 'a,
        S: ::embedded_tls::TlsCipherSuite + 'a,
    > packet_client::Connection for embedded_tls::TlsConnection<'a, C, S>
{
    async fn send(&mut self, buf: &[u8]) -> Result<(), error::PacketWriteError> {
        use ::embedded_io_async::Write;
        self.write_all(buf).await.map_err(|_| {
            error::PacketWriteError::ConnectionSend
        })
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<(), error::PacketReadError> {
        use ::embedded_io_async::Read;
        self
            .read_exact(buf)
            .await
            .map_err(|_| error::PacketReadError::ConnectionReceive)?;
        Ok(())
    }

    async fn receive_if_ready(&mut self, buf: &mut [u8]) -> Result<bool, error::PacketReadError> {
        self.receive(buf).await?;
        Ok(true)
    }
}
