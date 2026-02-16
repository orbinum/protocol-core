//! Note Management
//!
//! Structures and utilities for managing notes and wallet state.

use orbinum_encrypted_memo::MemoData;

/// Scanned note from the blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedNote {
    /// Note commitment
    pub commitment: [u8; 32],

    /// Leaf index in Merkle tree
    pub leaf_index: u64,

    /// Decrypted memo data
    pub memo_data: MemoData,

    /// Block number where note was created
    pub block_number: Option<u64>,

    /// Spent status
    pub is_spent: bool,
}

impl ScannedNote {
    /// Creates a new scanned note.
    pub fn new(commitment: [u8; 32], leaf_index: u64, memo_data: MemoData) -> Self {
        Self {
            commitment,
            leaf_index,
            memo_data,
            block_number: None,
            is_spent: false,
        }
    }

    /// Gets the note value.
    pub fn value(&self) -> u64 {
        self.memo_data.value
    }

    /// Gets the asset ID.
    pub fn asset_id(&self) -> u32 {
        self.memo_data.asset_id
    }

    /// Gets the owner public key.
    pub fn owner_pk(&self) -> &[u8; 32] {
        &self.memo_data.owner_pk
    }

    /// Gets the blinding factor.
    pub fn blinding(&self) -> &[u8; 32] {
        &self.memo_data.blinding
    }

    /// Marks note as spent.
    pub fn mark_as_spent(&mut self) {
        self.is_spent = true;
    }

    /// Checks if note is unspent.
    pub fn is_unspent(&self) -> bool {
        !self.is_spent
    }
}

/// Wallet balance by asset.
#[derive(Debug, Clone, Default)]
pub struct WalletBalance {
    balances: std::collections::HashMap<u32, u64>,
}

impl WalletBalance {
    /// Creates a new empty balance.
    pub fn new() -> Self {
        Self {
            balances: std::collections::HashMap::new(),
        }
    }

    /// Adds a note to the balance.
    pub fn add_note(&mut self, note: &ScannedNote) {
        if note.is_unspent() {
            let entry = self.balances.entry(note.asset_id()).or_insert(0);
            *entry += note.value();
        }
    }

    /// Gets balance for specific asset.
    pub fn get_balance(&self, asset_id: u32) -> u64 {
        *self.balances.get(&asset_id).unwrap_or(&0)
    }

    /// Gets all balances.
    pub fn get_all_balances(&self) -> &std::collections::HashMap<u32, u64> {
        &self.balances
    }

    /// Gets total number of assets.
    pub fn asset_count(&self) -> usize {
        self.balances.len()
    }
}

/// Note selector for choosing transaction inputs.
pub struct NoteSelector;

impl NoteSelector {
    /// Selects notes for a transfer using a greedy algorithm.
    ///
    /// Returns selected notes and change amount, or error if insufficient balance.
    pub fn select_notes_for_transfer(
        available_notes: &[ScannedNote],
        target_amount: u64,
        asset_id: u32,
    ) -> Result<(Vec<ScannedNote>, u64), &'static str> {
        // Filter notes by asset and unspent status
        let mut suitable_notes: Vec<_> = available_notes
            .iter()
            .filter(|n| n.asset_id() == asset_id && n.is_unspent())
            .cloned()
            .collect();

        if suitable_notes.is_empty() {
            return Err("No unspent notes available for this asset");
        }

        // Sort by value (descending) for greedy selection
        suitable_notes.sort_by_key(|note| core::cmp::Reverse(note.value()));

        let mut selected = Vec::new();
        let mut total = 0u64;

        // Greedy selection
        for note in suitable_notes {
            selected.push(note);
            total += selected.last().unwrap().value();

            if total >= target_amount {
                let change = total - target_amount;
                return Ok((selected, change));
            }
        }

        Err("Insufficient balance")
    }

    /// Selects exactly 2 notes for a transfer (required by circuit).
    ///
    /// Returns tuple of (note1, note2, change_amount).
    pub fn select_two_notes(
        available_notes: &[ScannedNote],
        target_amount: u64,
        asset_id: u32,
    ) -> Result<(ScannedNote, ScannedNote, u64), &'static str> {
        let (selected, change) =
            Self::select_notes_for_transfer(available_notes, target_amount, asset_id)?;

        if selected.len() < 2 {
            return Err("Need at least 2 notes for transfer circuit");
        }

        Ok((selected[0].clone(), selected[1].clone(), change))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_note(value: u64, asset_id: u32) -> ScannedNote {
        let memo = MemoData::new(value, [0u8; 32], [0u8; 32], asset_id);
        ScannedNote::new([0u8; 32], 0, memo)
    }

    #[test]
    fn test_scanned_note_basic() {
        let note = create_test_note(1000, 0);

        assert_eq!(note.value(), 1000);
        assert_eq!(note.asset_id(), 0);
        assert!(note.is_unspent());
        assert!(!note.is_spent);
    }

    #[test]
    fn test_note_mark_as_spent() {
        let mut note = create_test_note(1000, 0);

        assert!(note.is_unspent());

        note.mark_as_spent();

        assert!(note.is_spent);
        assert!(!note.is_unspent());
    }

    #[test]
    fn test_wallet_balance() {
        let mut balance = WalletBalance::new();

        let note1 = create_test_note(1000, 0); // ORB
        let note2 = create_test_note(500, 0); // ORB
        let note3 = create_test_note(200, 1); // USDT

        balance.add_note(&note1);
        balance.add_note(&note2);
        balance.add_note(&note3);

        assert_eq!(balance.get_balance(0), 1500); // ORB
        assert_eq!(balance.get_balance(1), 200); // USDT
        assert_eq!(balance.asset_count(), 2);
    }

    #[test]
    fn test_note_selector_sufficient_balance() {
        let notes = vec![
            create_test_note(1000, 0),
            create_test_note(500, 0),
            create_test_note(300, 0),
        ];

        let result = NoteSelector::select_notes_for_transfer(&notes, 1200, 0);

        assert!(result.is_ok());
        let (selected, change) = result.unwrap();

        assert_eq!(selected.len(), 2);
        assert_eq!(change, 300); // 1000 + 500 - 1200
    }

    #[test]
    fn test_note_selector_insufficient_balance() {
        let notes = vec![create_test_note(500, 0), create_test_note(300, 0)];

        let result = NoteSelector::select_notes_for_transfer(&notes, 1000, 0);

        assert!(result.is_err());
    }

    #[test]
    fn test_note_selector_exact_amount() {
        let notes = vec![create_test_note(1000, 0), create_test_note(500, 0)];

        let result = NoteSelector::select_notes_for_transfer(&notes, 1500, 0);

        assert!(result.is_ok());
        let (selected, change) = result.unwrap();

        assert_eq!(selected.len(), 2);
        assert_eq!(change, 0); // Exact amount
    }
}
