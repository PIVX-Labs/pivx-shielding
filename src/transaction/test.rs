#![cfg(test)]

use crate::transaction::create_transaction_internal;

use super::handle_transaction_internal;
use either::Either;
use jubjub::Fr;
use pivx_client_backend::encoding;

use pivx_client_backend::encoding::decode_extended_spending_key;
use pivx_client_backend::keys::UnifiedFullViewingKey;
use pivx_primitives::consensus::{BlockHeight, Network, Parameters, TEST_NETWORK};
use pivx_primitives::merkle_tree::CommitmentTree;
use pivx_primitives::sapling::value::NoteValue;
use pivx_primitives::sapling::Node;
use pivx_primitives::sapling::Note;
use pivx_primitives::sapling::Rseed::BeforeZip212;
use std::error::Error;
use std::io::Cursor;
use std::num::Wrapping;

#[test]
fn check_tx_decryption() {
    let mut tree = CommitmentTree::<Node>::empty();
    //TODO: remove the hardcoded bench32 value as soon as the pivx lib is updated; use TEST_NETWORK.hrp_sapling_extended_spending_key() instead.
    //This This pair (tx,key) has been generated on regtest and contains 1 shield note
    let skey = encoding::decode_extended_spending_key( "p-secret-spending-key-test", "p-secret-spending-key-test1qd7a5dwjqqqqpqyzy3xs3usw7rzal27gvx6szvt56qff69ceqxtzdst9cuvut3n7dcp28wk2why35qd3989hdvf5wq9m62q6xfrmnlkf0r70v2s7x63sr2zzt8shr6psry8sq66kvzwskrghutgd7wmqknsljq0j0t2kmyg8xzqweug0pg40ml0s8mvvmgmp9c9pdvmpnx9gnhwde9yrg4f2c36c808d6p29ywevmn47lp9elyawr93wxl96ttd5pevj6f68qc6rcps5u9990").expect("Cannot decode spending key");
    let tx = "0300000001a7d31ea039ab2a9914be2a84b6e8966758da5f8d1a64ac6fb49d2763dccc38da000000006b483045022100bb67345313edea3c7462c463ea8e03ef3b14caccfbefff9877ef246138427b6a02200b74211e1f27be080561c3985980e6b0e2e833f0751ea68dfb1e465b994afefc0121025c6802ec58464d8e65d5f01be0b7ce6e8404e4a99f28ea3bfe47efe40df9108cffffffff01e8657096050000001976a914b4f73d5c66d999699a4c38ba9fe851d7141f1afa88ac0000000001003665c4ffffffff00010b39ab5d98de6f5e3f50f3f075f61fea263b4cdd6927a53ac92c196be72911237f5041af34fed06560b8620e16652edf6d297d14a9cff2145731de6643d4bf13e189dbc4b6c4b91fe421133a2f257e5b516efd9b080814251ec0169fabdac1ce4a14575d3a42a7ca852c1ef6f6e1f3daf60e9ae4b77ef4d9a589dcbc09e8437fc28e80d6a0c4f1627b3e34ee9dd5cd587d1d57bab30e0a2eba893a6b61d7e53f5b49b4cb67a807e5db203b76744025d8395c83be2eb71009f9b82e78e7b65d9740340106ee59b22cd3628f1f10c3712c2b4f86464b627b27910cd3e0a80c5387798db4f15f751b5886beb1ab1a8c298185ed6f5d3a074689ba6e327e8dc2bd3b41790ecbe0240f909b8735b8ac98a59855b448e9f37d31d5d25b71959264c145abd15f0606ab5844391819afd4017890696272abad451dab8654d76e41c389941f0fd134d7d6e3b971b15cc63ba9bea421383639bdbeaa970636d637a1c6167154f39ded089d0f07776c58e8e86c0dac8259d22644e9d8a89456e9ccf2f66ce8633a9055f1703669c6a7b009865347ef608cb4ba8f3158e05947580ec50c32f69c0079dff58b3b53367f43490d4bcaba946ef4c42b4d366c66184f84ec442499a056b6b60eeaee94151459ac0b61eb6debfa96554bbe8ec39d2c49ee6eca48ed8dc137f84584803e2372ec35e0f9f4252beef9170419e703183fa87e7d35c2403b41700bc9f5d69da6c01c870515694f5c48372cba6bacd6a79ca1cdb85f38841f7680d0dd6853b22fc95d6e307419271edb05f2f40733c31c6f827eca592658716c5c73a9dd00a7e387250beffaa78bd1f104e031e00f014f9a50935864e11ffd655ea4d4c6c3d80b681e7581a19b2668c00528110ee5322add9dacb35b519280812050061788884cad7cc409a9261e86485cc4f2d904bdf40b3c78208a395a2488eb938b8a198b51ac418fa79e5d1d7bd8f96fe0910fe61136d8fe302f144745a988d6de83e89cd8befef8a762103aa32a14d93e3ac41b44188ab385b65c1f21cf29f19a6d2af556385dd60a994ecd1ac909488f7abce29e26690651a389d4466a9e20b7f08bfbdf4f4aa3e1577dc7debf1951688db8c75347d01e836f7816df3c7a7aaa833cbd6309d179d5dfc34045e52984cf475890f04b2ffcdf123175cc07568d08d9b8525ad9eabad231e1549a19fdce0fbb30c1fe7ec59bf8ed8e642ec6571456bdba8ade4458cffb1d65fee35242d7409de14a21514416a68e9c2d5c21eb9ca5813e1d8162a48d650ed7696b7b14b4f3d3f5eb892cf32614f62dea794e7f68e6d3d3ae6edf22e811f85e1ac7fe2a8437bdf287aa4d5ff842173039074516304042370a4e2feeb901319665ffc9b005b37c2afbea22faca316ea4f6b5f365fe46f679581966dadd029d687d2b400201";
    let key = UnifiedFullViewingKey::new(Some(skey.to_diversifiable_full_viewing_key()), None)
        .expect("Failed to create key");
    let (nullifiers, comp_note) = handle_transaction_internal(&mut tree, tx, &key, true).unwrap();
    //This was a t-s tx
    assert_eq!(nullifiers.len(), 0);
    //Successfully decrypt exactly 1 note
    assert_eq!(comp_note.len(), 1);
    let note = &comp_note[0].0;
    //Successfully decrypt the balance
    assert_eq!(note.value().inner(), 1000000000);
    //Successfully decrypt the payment address
    assert_eq!(
        encoding::encode_payment_address(
            TEST_NETWORK.hrp_sapling_payment_address(),
            &note.recipient()
        ),
        "ptestsapling1nkwhh4umfnze4u6wz4fgdy7hfrgp6hn7efc75xwwau6qdmmd79epgqmc9dqc58j7sffmy0lzhe7"
    );
}

#[test]
pub fn check_note_serialization() {
    let skey = encoding::decode_extended_spending_key( "p-secret-spending-key-test", "p-secret-spending-key-test1qd7a5dwjqqqqpqyzy3xs3usw7rzal27gvx6szvt56qff69ceqxtzdst9cuvut3n7dcp28wk2why35qd3989hdvf5wq9m62q6xfrmnlkf0r70v2s7x63sr2zzt8shr6psry8sq66kvzwskrghutgd7wmqknsljq0j0t2kmyg8xzqweug0pg40ml0s8mvvmgmp9c9pdvmpnx9gnhwde9yrg4f2c36c808d6p29ywevmn47lp9elyawr93wxl96ttd5pevj6f68qc6rcps5u9990").expect("Cannot decode spending key");

    let test_ser = Note::from_parts(
        skey.default_address().1,
        NoteValue::from_raw(10),
        BeforeZip212(Fr::one()),
    );
    let ser = serde_json::to_value(&test_ser).expect("Cannot serialize note");
    let test_deser: Note = serde_json::from_value(ser).expect("Cannot deserialize note");
    assert_eq!(test_deser.value(), test_ser.value());
    assert_eq!(test_deser.recipient(), test_ser.recipient());
    if let BeforeZip212(rseed) = test_deser.rseed() {
        assert_eq!(rseed, &Fr::one());
    } else {
        panic!();
    }
}

#[test]
pub fn test_create_transaction() -> Result<(), Box<dyn Error>> {
    let commitment_tree = Cursor::new(hex::decode("01579262d7062f79476e1aece5b7b8041ca4a9f05cdf86e5defbcfcc7122e51f4801927a1e0cc8d93a2e09aa9ebb671a99e79baae7d58507f19841612926a18f14700201a51e6b04344aa1ac6150116f345fc7738eeb8b4a547df6c55e3a12da025e8d3601364c5703f52e5480c057aa8b1edf1b53b727b251d5ae8fcb71706b2a9e02b429")?);
    let mut commitment_tree = CommitmentTree::<Node>::read(commitment_tree)?;
    let address =
        "ptestsapling1nfg50r63hd4u5xn0jt2rsw52jlndtqqt87azvaflh25j4kcw2p0ann4x7ae5x8yfqvyukhu2yxx";
    let extended_spending_key = decode_extended_spending_key(TEST_NETWORK.hrp_sapling_extended_spending_key(), "p-secret-spending-key-test1qv28ajgvqyqqpqxd5cm3tzpmvjdf097t38507xvf4yd9crwllezrj8xxg2w8gz9qxhsa8gldhdh5ep487mv8n2z7s3r76xd0k73tu4v42xrkzy4fucys9p9wstpalp5qre9tyxyt8ec6l42r3xv33jre9trkuy59p7ncjpqtx8nvefnnwj6v7g84hy0da6cxhpt6vyv7gq76eag0uyqevfejfzse4tgnqw94snev26an7lcnq9w9andgkxl4juk0p879c8cwp7axwas6a92kf").map_err(|_| "Failed to decode key")?;
    let key = UnifiedFullViewingKey::new(
        Some(extended_spending_key.to_diversifiable_full_viewing_key()),
        None,
    )
    .ok_or("Failed to construct key")?;
    let output = "yAHuqx6mZMAiPKeV35C11Lfb3Pqxdsru5D";
    let input_tx = "0300000001a347f398c8957afee7ef0fae759ff29feda25f3e72ab5052ea09729389fd48ca000000006b483045022100c332effdceaa20b3225d52d20059e443ed112d561329b81f78a9db338637e6a102204f948d70c37bfe96bbe776f8279ad5fa857c638338d8ce49f553a3ec60993d8f0121025c6802ec58464d8e65d5f01be0b7ce6e8404e4a99f28ea3bfe47efe40df9108cffffffff01e89bd55a050000001976a9147888a1affe25e5c7af03fffdbea29f13ee1be22b88ac0000000001006cca88ffffffff000150585de8e31e6c65dfa07981275f13ebb8c9c67d8c7d088622aacca6c35c67a23642ad16653acda3cf9b5230f652592197e578ea1eae78c2496a3dc274a4ba0b522216af4c44abd4e9b81964d0a801929df1cb543c4fea041d056cc493b2f8dd90db662a0a43dae4d80a8cb0bd93e22b7000c0bcdab93f94800b88268a78a4d77147f2f16bde98b2386e5ac4025260df5f63adaef13bc8d7a920dbd14fa7e8ef0c5ff29f00942341e29b15509bfa99b4b1bd0ba29c5cf2c419113c27288b3a8d8f4919a4845e47d4e5fe1d1081a98e0ee49bb0e422b339e949276a1264c236850d9beb94c7855143a4f00689d1bf8d996eee9f0ee865ca780713f5aa1990aa848d47a39ea45c926141a1ff5a5a45c2e2e78d470a180e02b3dd47e0b206a4542d4dbfc540023ee5cb35e54a086942657232c27a15c87eef6dd11587e871ea690a45002e0b60605d7c4ac7fde81a71aadde9d0cc0d5c347fbe942993bd2a69ca2ca98ea0885454e7387d609192094bea075b96f020a8ed7080b5ef0aaf13e73da67a68e377db62720724e8c0d2913487be2a3e39380b33a90f0336f07fa031345a42784460356987da3227bd40a8cf933e4b8661020cf566af785a5c9b404c84153a69d9280739cb567c6cdf41f7a1a38b4d5847b33956b4dfa847b386850eff2a3e9fe7434fb551d1c6d31fae868a2f491ebd4f382a0ac203652f4be9fb3cff3ed10e6295639af76a41e40e562862d4359e4874b565aa1bae4b68abb0a7fe66884b75250d16276521925ead4821c7f04338286c2e52e7772f980d7a228ad2b89c18c8eeaf3ee1b4d5c5a959fc93c1cda3f9340f8256a88076b96a8718efc5dcb3733e3e11f6ca1198a97a248ff4ab0a7e883e360b8495470badc7ec75f84e58d87ff83d03c594a11b9029177efa5fea026a71c2c328a6356bd447eb154ac39e43963118033fc1a72702b12e641e7dfa8f98a58e43d75f6b3350af9fc54e683c6074cfd76e86752d7f598b6816696a4f17ba5f10c983ad2f8e102f44f42b2d07b24fb599abbfd067373c4b00f9ae830fcdd79ca8fa8c90eb414f8f5bb070d1199b9e9fae7124772865e0d6f486d7f10f073a0d61bd9e8c94b7a963c831e76b5c07cef22c06877a683aca53396289b115f8b59989f3d5906c4961891ef4677ce73d752ee0ba8929056f38d7630b02db2188d512d733126fa2479217dcd5ed4061928e5ba374300d7a5fa08af2b64cbf5a2176e07b3a4a5bb4812c46c2e608d364d8589225f9b7620116e0cd6a175ab397d295ff0ee0100d2415db6c6736a0f6e2248a62c4c47b39103f67e30814cf3c9b0b82936546d4b81826cd8fdebe24ae91a81b69e7188f4b18c3422d61b367bc4ca92f8815c0fc42caf524b3337a8b9a6737557e1d471745e02a8e88a19fe730e224126d290a";

    let (_nullifiers, notes) =
        handle_transaction_internal(&mut commitment_tree, input_tx, &key, true)?;
    assert_eq!(notes.len(), 1);
    let (note, path) = &notes[0];
    let mut path_vec = vec![];
    path.write(&mut path_vec)?;
    let path = hex::encode(path_vec);
    let tx = create_transaction_internal(
        Either::Left(vec![(note.clone(), path)]),
        &extended_spending_key,
        output,
        address,
        5 * 10e6 as u64,
        BlockHeight::from_u32(317),
        Network::TestNetwork,
    )?;

    assert_eq!(tx.nullifiers.len(), 1);
    let nullifier = tx.nullifiers[0].to_string();
    assert_eq!(
        nullifier,
        "57af9d8b344e1b37d91b5cdaa2b99e17f67049ce86e2d05aaa9d3e7b25feba91"
    );
    // When we implement mempool, test that new notes work correctly

    Ok(())
}
