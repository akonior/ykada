use std::time::Duration;

use serde::{de::IgnoredAny, Deserialize, Serialize};

use crate::error::{YkadaError, YkadaResult};
use crate::model::{Network, Utxo};
use crate::ports::{TipFetcher, TxSubmitter, UtxoFetcher};

#[derive(Serialize)]
struct AddressRequest<'a> {
    #[serde(rename = "_addresses")]
    addresses: &'a [&'a str],
}

#[derive(Deserialize)]
struct KoiosAddressInfo {
    utxo_set: Vec<KoiosUtxo>,
}

#[derive(Deserialize)]
struct KoiosUtxo {
    tx_hash: String,
    tx_index: u64,
    value: String,
    asset_list: Vec<IgnoredAny>,
}

#[derive(Deserialize)]
struct KoiosTip {
    abs_slot: u64,
}

pub(crate) struct KoiosClient {
    base_url: &'static str,
    agent: ureq::Agent,
}

impl KoiosClient {
    pub(crate) fn for_network(network: Network) -> Self {
        Self {
            base_url: match network {
                Network::Mainnet => "https://api.koios.rest/api/v1",
                Network::Preprod => "https://preprod.koios.rest/api/v1",
                Network::Preview => "https://preview.koios.rest/api/v1",
            },
            // Bounded timeouts so a stalled/broken Koios endpoint can't hang the CLI.
            agent: ureq::Agent::new_with_config(
                ureq::Agent::config_builder()
                    .timeout_connect(Some(Duration::from_secs(5)))
                    .timeout_send_body(Some(Duration::from_secs(30)))
                    .timeout_recv_response(Some(Duration::from_secs(30)))
                    .timeout_recv_body(Some(Duration::from_secs(30)))
                    .build(),
            ),
        }
    }

    fn fetch_address_info(&self, address: &str) -> YkadaResult<Option<KoiosAddressInfo>> {
        let url = format!("{}/address_info", self.base_url);
        let body = AddressRequest {
            addresses: &[address],
        };
        let response: Vec<KoiosAddressInfo> = self
            .agent
            .post(&url)
            .send_json(body)?
            .into_body()
            .read_json()?;
        Ok(response.into_iter().next())
    }
}

impl UtxoFetcher for KoiosClient {
    fn fetch_utxos(&self, address: &str) -> YkadaResult<Vec<Utxo>> {
        let Some(info) = self.fetch_address_info(address)? else {
            return Ok(vec![]);
        };

        info.utxo_set
            .into_iter()
            .map(|u| {
                let lovelace = u
                    .value
                    .parse::<u64>()
                    .map_err(|_| YkadaError::Network("invalid UTxO value".into()))?;
                Ok(Utxo {
                    tx_hash: u.tx_hash,
                    tx_index: u.tx_index,
                    lovelace,
                    has_tokens: !u.asset_list.is_empty(),
                })
            })
            .collect()
    }
}

impl TipFetcher for KoiosClient {
    fn fetch_tip_slot(&self) -> YkadaResult<u64> {
        let url = format!("{}/tip", self.base_url);
        let response: Vec<KoiosTip> = self.agent.get(&url).call()?.into_body().read_json()?;
        response
            .into_iter()
            .next()
            .map(|t| t.abs_slot)
            .ok_or_else(|| YkadaError::Network("empty tip response".into()))
    }
}

// Koios spreads requests over several instances. One that has lost its node connection
// answers TxCmdTxSubmitConnectionError before the tx reaches any node, so a retry is safe.
// Timeouts are not retried: the tx may already have been submitted.
const SUBMIT_ATTEMPTS: usize = 3;
const SUBMIT_RETRY_DELAY: Duration = Duration::from_secs(2);

enum SubmitError {
    NodeUnreachable(YkadaError),
    Rejected(YkadaError),
}

impl From<SubmitError> for YkadaError {
    fn from(failure: SubmitError) -> Self {
        match failure {
            SubmitError::NodeUnreachable(e) | SubmitError::Rejected(e) => e,
        }
    }
}

fn classify_submit_failure(code: u16, body: String) -> SubmitError {
    // Bound the error body so a hostile/huge response can't blow up the message.
    let shown: String = body.chars().take(256).collect();
    let error = YkadaError::Network(format!("HTTP {code}: {shown}"));
    match body.contains("TxCmdTxSubmitConnectionError") {
        true => SubmitError::NodeUnreachable(error),
        false => SubmitError::Rejected(error),
    }
}

fn submit_with_retry(
    attempts: usize,
    delay: Duration,
    mut submit: impl FnMut() -> Result<(), SubmitError>,
) -> Result<(), SubmitError> {
    let first = submit();
    (1..attempts).fold(first, |attempt, _| match attempt {
        Err(SubmitError::NodeUnreachable(_)) => {
            std::thread::sleep(delay);
            submit()
        }
        finished => finished,
    })
}

impl KoiosClient {
    fn submit_once(&self, signed_tx_cbor: &[u8]) -> Result<(), SubmitError> {
        let url = format!("{}/submittx", self.base_url);
        // Keep error responses as responses: their body tells a rejection from a lost node.
        let response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/cbor")
            .config()
            .http_status_as_error(false)
            .build()
            .send(signed_tx_cbor)
            .map_err(|e| SubmitError::Rejected(YkadaError::Network(e.to_string())))?;
        let status = response.status();
        match status.is_success() {
            true => Ok(()),
            false => Err(classify_submit_failure(
                status.as_u16(),
                response.into_body().read_to_string().unwrap_or_default(),
            )),
        }
    }
}

impl TxSubmitter for KoiosClient {
    fn submit_tx(&self, signed_tx_cbor: &[u8]) -> YkadaResult<()> {
        submit_with_retry(SUBMIT_ATTEMPTS, SUBMIT_RETRY_DELAY, || {
            self.submit_once(signed_tx_cbor)
        })
        .map_err(YkadaError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    const UNREACHABLE_BODY: &str = r#"{"contents":{"contents":"Network.Socket.connect: <socket: 14>: does not exist (No such file or directory)","tag":"TxCmdTxSubmitConnectionError"},"tag":"TxSubmitFail"}"#;
    const REJECTED_BODY: &str = r#"{"contents":{"contents":{"contents":{"era":"ShelleyBasedEraConway"},"tag":"TxValidationErrorInCardanoMode"},"tag":"TxCmdTxSubmitValidationError"},"tag":"TxSubmitFail"}"#;

    fn unreachable() -> SubmitError {
        classify_submit_failure(400, UNREACHABLE_BODY.into())
    }

    fn run(outcomes: Vec<fn() -> Result<(), SubmitError>>) -> (Result<(), SubmitError>, usize) {
        let calls = Cell::new(0);
        let result = submit_with_retry(3, Duration::ZERO, || {
            calls.set(calls.get() + 1);
            outcomes[(calls.get() - 1).min(outcomes.len() - 1)]()
        });
        (result, calls.get())
    }

    #[test]
    fn test_connection_error_is_retryable() {
        assert!(matches!(unreachable(), SubmitError::NodeUnreachable(_)));
    }

    #[test]
    fn test_validation_error_is_final() {
        let failure = classify_submit_failure(400, REJECTED_BODY.into());
        assert!(matches!(failure, SubmitError::Rejected(_)));
    }

    #[test]
    fn test_retries_until_a_node_accepts() {
        let (result, calls) = run(vec![
            || Err(unreachable()),
            || Err(unreachable()),
            || Ok(()),
        ]);
        assert!(result.is_ok());
        assert_eq!(calls, 3);
    }

    #[test]
    fn test_gives_up_after_the_last_attempt() {
        let (result, calls) = run(vec![|| Err(unreachable())]);
        assert!(matches!(result, Err(SubmitError::NodeUnreachable(_))));
        assert_eq!(calls, 3);
    }

    #[test]
    fn test_does_not_retry_a_rejected_tx() {
        let (result, calls) = run(vec![|| {
            Err(classify_submit_failure(400, REJECTED_BODY.into()))
        }]);
        assert!(matches!(result, Err(SubmitError::Rejected(_))));
        assert_eq!(calls, 1);
    }

    // Answers one request on localhost with the given status and body; returns its URL.
    fn serve_once(status: u16, body: &'static str) -> &'static str {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let length = request_content_length(&mut reader);
            reader.read_exact(&mut vec![0; length]).unwrap();
            write!(
                &stream,
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        Box::leak(url.into_boxed_str())
    }

    // Reads the request headers and returns the body length.
    fn request_content_length(reader: &mut impl BufRead) -> usize {
        reader
            .lines()
            .map(Result::unwrap)
            .take_while(|line| !line.is_empty())
            .fold(0, |length, line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map_or(length, |n| n.trim().parse().unwrap())
            })
    }

    fn client(base_url: &'static str) -> KoiosClient {
        KoiosClient {
            base_url,
            ..KoiosClient::for_network(Network::Preview)
        }
    }

    #[test]
    fn test_submit_accepts_a_success_status() {
        assert!(client(serve_once(202, "\"ok\""))
            .submit_once(&[0x84])
            .is_ok());
    }

    #[test]
    fn test_submit_reads_the_body_of_an_error_status() {
        let unreachable = client(serve_once(400, UNREACHABLE_BODY)).submit_once(&[0x84]);
        assert!(matches!(unreachable, Err(SubmitError::NodeUnreachable(_))));

        let rejected = client(serve_once(400, REJECTED_BODY)).submit_once(&[0x84]);
        assert!(matches!(rejected, Err(SubmitError::Rejected(e))
            if e.to_string().contains("HTTP 400") && e.to_string().contains("TxCmdTxSubmitValidationError")));
    }
}
