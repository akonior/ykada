use crate::error::{YkadaError, YkadaResult};
use crate::model::Utxo;

// Largest-first greedy selection over ADA-only UTxOs (token-bearing ones are skipped,
// since outputs carry lovelace only). Returns (indices into `utxos`, total lovelace).
pub(crate) fn select_inputs(utxos: &[Utxo], required: u64) -> YkadaResult<(Vec<usize>, u64)> {
    let mut indices: Vec<usize> = (0..utxos.len()).filter(|&i| !utxos[i].has_tokens).collect();
    indices.sort_by(|&a, &b| utxos[b].lovelace.cmp(&utxos[a].lovelace));

    let (selected, total) = indices.into_iter().try_fold(
        (vec![], 0u64),
        |(mut acc, sum), i| -> YkadaResult<(Vec<usize>, u64)> {
            if sum >= required {
                Ok((acc, sum))
            } else {
                acc.push(i);
                let next = sum
                    .checked_add(utxos[i].lovelace)
                    .ok_or_else(|| YkadaError::Tx("total input value overflows u64".into()))?;
                Ok((acc, next))
            }
        },
    )?;

    if total < required {
        return Err(YkadaError::InsufficientFunds {
            have: total,
            need: required,
        });
    }

    Ok((selected, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(lovelace: u64) -> Utxo {
        Utxo {
            tx_hash: "00".repeat(32),
            tx_index: 0,
            lovelace,
            has_tokens: false,
        }
    }

    #[test]
    fn test_picks_largest_first() {
        let utxos = [5_000_000, 3_000_000, 10_000_000].map(utxo);
        let selected = select_inputs(&utxos, 6_000_000).unwrap();
        assert_eq!(selected, (vec![2], 10_000_000));
    }

    #[test]
    fn test_combines_utxos_when_one_is_not_enough() {
        let utxos = [3_000_000, 3_000_000].map(utxo);
        let selected = select_inputs(&utxos, 5_000_000).unwrap();
        assert_eq!(selected, (vec![0, 1], 6_000_000));
    }

    #[test]
    fn test_skips_token_utxos() {
        let with_tokens = Utxo {
            has_tokens: true,
            ..utxo(50_000_000)
        };
        let selected = select_inputs(&[with_tokens, utxo(5_000_000)], 3_000_000).unwrap();
        assert_eq!(selected, (vec![1], 5_000_000));
    }

    #[test]
    fn test_overflow_errors() {
        let utxos = [u64::MAX - 5, 10].map(utxo);
        let msg = select_inputs(&utxos, u64::MAX).unwrap_err().to_string();
        assert!(msg.contains("overflows"), "got: {msg}");
    }
}
