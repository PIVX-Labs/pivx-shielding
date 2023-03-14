import bs58 from 'bs58';

export default class PIVXShielding {
  /**
   * Creates a PIVXShielding object
   * @param {Object} o - options
   * @param {Array<Number>?} o.seed - array of 32 bytes that represents a random seed.
   * @param {String?} o.extendedSpendingKey - Extended Spending Key.
   * @param {Number} o.blockHeight - number representing the block height of creation of the wallet
   * @param {Number} o.coinType - number representing the coin type, 1 represents testnet
   * @param {Number} o.accountIndex - index of the account that you want to generate, by default is set to 0
   */
  static async create({
    seed,
    extendedSpendingKey,
    blockHeight,
    coinType,
    accountIndex = 0,
  }) {
    if (!extendedSpendingKey && !seed) {
      throw new Error("One of seed or extendedSpendingKey must be provided");
    }

    const shieldMan = await import("pivx-shielding");

    if (!extendedSpendingKey) {
      const serData = {
        seed: seed,
        coin_type: coinType,
        account_index: accountIndex,
      };
      extendedSpendingKey =
        shieldMan.generate_extended_spending_key_from_seed(serData);
    }
    const isTestNet = coinType == 1 ? true : false;
    const [effectiveHeight, commitmentTree] = shieldMan.get_closest_checkpoint(
      blockHeight,
      isTestNet
    );

    return new PIVXShielding(
      shieldMan,
      extsk,
      isTestNet,
      effectiveHeight,
      commitmentTree
    );
  }

  constructor(shieldMan, extsk, isTestNet, commitmentTree) {
    /**
     * Webassembly object that holds Shield related functions
     * @private
     */
    this.shieldMan = shieldMan;
    /**
     * Extended spending key
     * @type {String}
     * @private
     */
    this.extsk = extsk;
    /**
     * Number of generated addresses
     * @type {Number}
     * @private
     */
    this.generatedAddresses = 0;
    /**
     * @type {Boolean}
     * @private
     */
    this.isTestNet = isTestNet;
    /**
     * Hex encoded commitment tree
     * @type {String}
     * @private
     */
    this.commitmentTree = commitmentTree;
    /**
     * Hex encoded unspent notes (UTXO equivalent in shield)
     * @type {String[]}
     * @private
     */
    this.unspentNotes = [];

    /**
     * @type {Map<String, String[]>} A map txid->nullifiers, storing pending transaction.
     * @private
     */
    this.pendingTransactions = new Map();
  }

  /**
   * Loop through the txs of a block and update useful shield data
   * @param {{tx: String[]}} blockJson - Json of the block outputted from any PIVX node
   */
  handleBlock(blockJson) {
    for (const tx of blockJson.tx) {
      this.addTransaction(tx.hex);
    }
  }
  /**
   * Adds a transaction to the tree. Decrypts notes and stores nullifiers
   * @param {String} hex - transaction hex
   */
  addTransaction(hex) {
    const res = this.shieldMan.handle_transaction(
      this.commitmentTree,
      hex,
      this.extsk,
      this.isTestNet
    );
    this.commitmentTree = res.commitment_tree;
    for (const x of res.decrypted_notes) {
      this.unspentNotes.push(x);
    }
    if (res.nullifiers.length > 0) {
      this.removeSpentNotes(res.nullifiers);
    }
  }

  /**
   * Remove the Shield Notes that match the nullifiers given in input
   * @param {Array<String>} blockJson - Array of nullifiers
   */
  removeSpentNotes(nullifiers) {
    this.unspentNotes = this.shieldMan.remove_spent_notes(
      this.unspentNotes,
      nullifiers,
      this.extsk,
      this.isTestNet
    );
  }
  /**
   * Return number of shielded satoshis of the account
   */
  getBalance() {
    return this.unspentNotes.reduce((acc, [note]) => acc + note.value, 0);
  }

  /**
   * Createes a transaction, sending `amount` satoshis to the address
   * @param {{address: String, amount: Number}} target
   */
  createTransaction({address, amount, blockHeight, useShieldInputs = true}) {
    const { txid, txhex, nullifiers } = this.shieldMan.create_transaction({
      notes: useShieldInputs ? this.unspentNotes : null,
      utxos: useShieldInputs ? null : this.utxos,
      extsk: this.extsk,
      to_address: address,
      change_address: this.getNewAddress(),
      amount,
      block_height: blockHeight,
      is_testnet: this.isTestnet,
    });

    this.pendingTransactions.set(txid, nullifiers);

    return txhex;
  }

  /**
   * Signals the class that a transaction was sent successfully
   * and the notes can be marked as spent
   * @throws Error if txid is not found
   * @param{String} txid - Transaction id
   */
  finalizeTransaction(txid) {
    const nullifiers = this.pendingTransactions.get(txid);
    if (!nullifiers) {
      throw new Error(`Unknown transaction ${txid}`);
    }
    this.removeSpentNullifiers(nullifiers);
  }
  /**
   * Discards the transaction, for example if
   * there were errors in sending them.
   * The notes won't be marked as spent.
   * @param{String} txid - Transaction id
   */
  discardTransaction(txid) {
    this.pendingTransactions.clear(txid);
  }

  /**
   * @returns {String} new shielded address
   */
  getNewAddress() {
    const address = this.shieldMan.generate_next_shielding_payment_address(
      this.extsk,
      this.generatedAddresses + 1,
      this.isTestNet
    );
    this.generatedAddresses += 1;
    return address;
  }

  /**
   * Add a transparent UTXO, along with its private key
   * @param {Object} o - Options
   * @param {String} o.txid - Transaction ID of the UTXO
   * @param {Number} o.vout - output index of the UTXO
   * @param {Number} o.amount - Value in satoshi of the UTXO
   * @param {String} o.privateKey - Private key associated to the UTXO
   * @param {Uint8Array} o.script - Tx Script
   */
  addUTXO({txid, vout, amount, privateKey, script}) {
    const wifBytes = bs58.decode(privateKey);
    this.utxos.push({
      txid,
      vout,
      amount,
      private_key: wifBytes.slice(1, 33),
      script,
    });
  }
}
