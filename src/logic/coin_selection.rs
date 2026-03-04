use crate::error::{YkadaError, YkadaResult};
use crate::model::Utxo;

/// Largest-first greedy coin selection.
/// Returns (selected UTxO indices into `utxos`, total lovelace selected).
pub fn select_inputs(utxos: &[Utxo], required: u64) -> YkadaResult<(Vec<usize>, u64)> {
    let mut indices: Vec<usize> = (0..utxos.len()).collect();
    indices.sort_by(|&a, &b| utxos[b].lovelace.cmp(&utxos[a].lovelace));

    let (selected, total) = indices.into_iter().try_fold(
        (vec![], 0u64),
        |(mut acc, sum), i| -> YkadaResult<(Vec<usize>, u64)> {
            if sum >= required {
                Ok((acc, sum))
            } else {
                acc.push(i);
                Ok((acc, sum + utxos[i].lovelace))
            }
        },
    )?;

    if total < required {
        return Err(YkadaError::NetworkError(format!(
            "insufficient funds: have {total} lovelace, need {required}"
        )));
    }

    Ok((selected, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_utxo(tx_hash: &str, lovelace: u64) -> Utxo {
        Utxo {
            tx_hash: tx_hash.into(),
            tx_index: 0,
            lovelace,
            tokens: vec![],
        }
    }

    #[test]
    fn test_coin_selection_largest_first() {
        // Three UTxOs: 5 ADA, 3 ADA, 10 ADA — need 6 ADA
        // Largest-first: picks 10 ADA (1 UTxO), total = 10 >= 6
        let utxos = vec![
            fake_utxo(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                5_000_000,
            ),
            fake_utxo(
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                3_000_000,
            ),
            fake_utxo(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                10_000_000,
            ),
        ];
        let (selected, total) = select_inputs(&utxos, 6_000_000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], 2);
        assert_eq!(total, 10_000_000);
    }

    #[test]
    fn test_coin_selection_insufficient_funds() {
        let utxos = vec![fake_utxo(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1_000_000,
        )];
        let result = select_inputs(&utxos, 5_000_000);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("insufficient funds"), "got: {msg}");
    }

    #[test]
    fn test_coin_selection_multiple_utxos() {
        // Two UTxOs of 3 ADA each — need 5 ADA
        // Picks both (3 + 3 = 6 >= 5)
        let utxos = vec![
            fake_utxo(
                "1111111111111111111111111111111111111111111111111111111111111111",
                3_000_000,
            ),
            fake_utxo(
                "2222222222222222222222222222222222222222222222222222222222222222",
                3_000_000,
            ),
        ];
        let (selected, total) = select_inputs(&utxos, 5_000_000).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(total, 6_000_000);
    }
}
