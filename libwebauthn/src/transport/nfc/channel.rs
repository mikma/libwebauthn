use apdu::core::HandleError;
use apdu::{Command, Response, command};
use apdu_core;
use async_trait::async_trait;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;
use tokio::sync::mpsc;
#[allow(unused_imports)]
use tracing::{Level, debug, instrument, trace, warn};

use crate::UxUpdate;
use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::transport::channel::{AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::{Error, TransportError};

use super::commands::{command_ctap_msg, command_get_response};

const SELECT_P1: u8 = 0x04;
const SELECT_P2: u8 = 0x00;
const APDU_FIDO: &[u8; 8] = b"\xa0\x00\x00\x06\x47\x2f\x00\x01";
const SW1_MORE_DATA: u8 = 0x61;

#[derive(thiserror::Error)]
pub enum NfcError {
    /// APDU error returned by the card.
    Apdu(#[from] apdu::Error),

    /// Unexpected error occurred on the device.
    Device(Box<dyn Display>),
}

impl Debug for NfcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for NfcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NfcError::Apdu(e) => Display::fmt(e, f),
            NfcError::Device(e) => e.fmt(f),
        }
    }
}

impl From<NfcError> for Error {
    fn from(input: NfcError) -> Self {
        trace!("{:?}", input);
        let output = match input {
            NfcError::Apdu(_apdu_error) => TransportError::InvalidFraming,
            NfcError::Device(_) => TransportError::ConnectionLost,
        };
        Error::Transport(output)
    }
}

pub trait HandlerInCtx<Ctx> {
    /// Handles the APDU command in a specific context.
    /// Implementations must transmit the command to the card through a reader,
    /// then receive the response from them, returning length of the data written.
    fn handle_in_ctx(&mut self, ctx: Ctx, command: &[u8], response: &mut [u8])
    -> apdu_core::Result;
}

pub trait NfcBackend<Ctx>: HandlerInCtx<Ctx> + Display {}

pub struct NfcChannel<Ctx>
where
    Ctx: Copy + Sync,
{
    delegate: Box<dyn NfcBackend<Ctx> + Send + Sync>,
    auth_token_data: Option<AuthTokenData>,
    tx: mpsc::Sender<UxUpdate>,
    ctx: Ctx,
    apdu_response: Option<ApduResponse>,
    cbor_response: Option<CborResponse>,
    supported: SupportedProtocols,
    status: ChannelStatus,
}

impl<Ctx> Display for NfcChannel<Ctx>
where
    Ctx: Copy + Send + Sync,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.delegate)
    }
}

impl<Ctx> NfcChannel<Ctx>
where
    Ctx: fmt::Debug + Display + Copy + Send + Sync,
{
    pub fn new(
        delegate: Box<dyn NfcBackend<Ctx> + Send + Sync>,
        ctx: Ctx,
        tx: mpsc::Sender<UxUpdate>,
    ) -> Self {
        NfcChannel {
            delegate,
            auth_token_data: None,
            tx,
            ctx,
            apdu_response: None,
            cbor_response: None,
            supported: SupportedProtocols {
                fido2: false,
                u2f: false,
            },
            status: ChannelStatus::Ready,
        }
    }

    #[instrument(skip_all)]
    pub async fn wink(&mut self, _timeout: Duration) -> Result<bool, Error> {
        warn!("WINK capability is not supported");
        return Ok(false);
    }

    pub fn select_fido2(&mut self) -> Result<(), Error> {
        let command = command::select_file(SELECT_P1, SELECT_P2, APDU_FIDO);
        let is_u2f_v2 = self.handle(self.ctx, command).map(|e| (e == b"U2F_V2"))?;
        self.supported = SupportedProtocols {
            u2f: is_u2f_v2,
            // A CTAP authenticatorGetInfo should be issued to
            // determine if the device supports CTAP2 or
            // not. Assume it does for now.
            fido2: true,
        };

        Ok(())
    }

    fn handle_in_ctx(
        &mut self,
        ctx: Ctx,
        command_buf: &Vec<u8>,
        buf: &mut [u8],
    ) -> Result<usize, NfcError> {
        self.delegate
            .handle_in_ctx(ctx, &command_buf, buf)
            .map_err(|e| match e {
                HandleError::NotEnoughBuffer(l) => {
                    NfcError::Device(Box::new(HandleError::NotEnoughBuffer(l)))
                }
                HandleError::Nfc(e) => NfcError::Device(e),
            })
    }

    pub fn handle<'a>(
        &'a mut self,
        ctx: Ctx,
        command: impl Into<Command<'a>>,
    ) -> Result<Vec<u8>, NfcError> {
        let command = command.into();
        let command_buf = Vec::from(command);

        let mut buf = [0u8; 1024];
        let mut rapdu = Vec::new();

        let len: usize = self.handle_in_ctx(ctx, &command_buf, &mut buf)? as usize;
        let mut resp = Response::from(&buf[..len]);

        let (mut sw1, mut sw2) = resp.trailer;
        rapdu.extend_from_slice(resp.payload);

        while sw1 == SW1_MORE_DATA {
            let get_response_cmd = command_get_response(0x00, 0x00, sw2);
            let get_response_buf = Vec::from(get_response_cmd);
            let len = self.handle_in_ctx(ctx, &get_response_buf, &mut buf)?;
            resp = Response::from(&buf[..len]);
            (sw1, sw2) = resp.trailer;
            rapdu.extend_from_slice(resp.payload);
        }

        rapdu.extend_from_slice(&[sw1, sw2]);
        Result::from(Response::from(rapdu.as_slice()))
            .map(|p| p.to_vec())
            .map_err(|e| {
                trace!("map_err {:?}", e);
                apdu::Error::from(e).into()
            })
    }
}

#[async_trait]
impl<'a, Ctx> Channel for NfcChannel<Ctx>
where
    Ctx: Copy + Send + Sync + fmt::Debug + Display,
{
    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(self.supported)
    }

    async fn status(&self) -> ChannelStatus {
        self.status
    }

    async fn close(&mut self) {
        todo!("close")
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_send(&self, request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        todo!("apdu_send")
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_recv(&self, _timeout: Duration) -> Result<ApduResponse, Error> {
        todo!("apdu_recv")
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        _timeout: std::time::Duration,
    ) -> Result<(), Error> {
        let data = &request.ctap_hid_data();
        let mut rest: &[u8] = data;

        while rest.len() > 250 {
            let to_send = &rest[..250];
            rest = &rest[250..];
            let ctap_msg = command_ctap_msg(true, to_send);
            let resp = self.handle(self.ctx, ctap_msg)?;
            trace!("cbor_send has_more {:?} {:?}", to_send, resp);
        }

        let ctap_msg = command_ctap_msg(false, rest);
        let resp = self.handle(self.ctx, ctap_msg)?;
        trace!("cbor_send {:?} {:?}", rest, resp);

        // FIXME check for SW_UPDATE?

        // let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        // let (mut resp, mut sw1, mut sw2) = self.card
        //     .chain_apdus(0x80, 0x10, 0x80, 0x00, data, &mut rapdu_buf)
        //     .expect("APDU exchange failed");

        // loop {
        //     while (sw1, sw2) == SW_UPDATE {
        //         // ka_status = STATUS(resp[0])
        //         // if on_keepalive and last_ka != ka_status:
        //         //     last_ka = ka_status
        //         //     on_keepalive(ka_status)
        //         // NFCCTAP_GETRESPONSE

        //         (resp, sw1, sw2) = self.card
        //             .chain_apdus(0x80, 0x11, 0x00, 0x00, &[], &mut rapdu_buf).expect("APDU chained exchange failed");
        //         debug!("Error {:?} {:?}", sw1, sw2);
        //     }

        //     if (sw1, sw2) != SW_SUCCESS {
        //         return Err(Error::Transport(TransportError::InvalidFraming));
        //     }

        let cbor_response = CborResponse::try_from(&resp)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        self.cbor_response = Some(cbor_response);
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_recv(&mut self, _timeout: std::time::Duration) -> Result<CborResponse, Error> {
        self.cbor_response
            .take()
            .ok_or(Error::Transport(TransportError::InvalidFraming))
    }

    fn get_state_sender(&self) -> &mpsc::Sender<UxUpdate> {
        &self.tx
    }
}

impl<Ctx> Ctap2AuthTokenStore for NfcChannel<Ctx>
where
    Ctx: Copy + Send + Sync,
{
    fn store_auth_data(&mut self, auth_token_data: AuthTokenData) {
        self.auth_token_data = Some(auth_token_data);
    }

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        self.auth_token_data.as_ref()
    }

    fn clear_uv_auth_token_store(&mut self) {
        self.auth_token_data = None;
    }
}
