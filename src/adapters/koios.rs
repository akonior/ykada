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
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout_read(Duration::from_secs(30))
                .timeout_write(Duration::from_secs(30))
                .build(),
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
            .set("Content-Type", "application/json")
            .send_json(body)?
            .into_json()?;
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
        let response: Vec<KoiosTip> = self
            .agent
            .get(&url)
            .set("Content-Type", "application/json")
            .call()?
            .into_json()?;
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
        self.agent
            .post(&url)
            .set("Content-Type", "application/cbor")
            .send_bytes(signed_tx_cbor)
            .map(|_| ())
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    classify_submit_failure(code, resp.into_string().unwrap_or_default())
                }
                other => SubmitError::Rejected(YkadaError::Network(other.to_string())),
            })
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
}
