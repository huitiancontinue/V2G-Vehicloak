package main

import (
	"bytes"
	"fmt"
	//"github.com/ethereum/go-ethereum/crypto"
	//"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/zktx"
)

func main() {

	/*
	*test mint
	 */
	// //value_old := uint64(0)
	// sn_old := common.HexToHash("0x364d3f5af0cc140746b48072ff1ba28c12d84106bdcdf66e7a26c68f70e5f04c")
	// fmt.Println("sn_old:", sn_old.Hex())
	// r_old := common.HexToHash("0x80f10f96535550f7be47e0f7477ddec9d2d94b0df3bff810a97f9fd383104d3f")
	// fmt.Println("r_old:", r_old.Hex())

	// //value := uint64(10000)
	// sn := common.HexToHash("0xbdba1ea395c9bfc41f666440c1030e1d705f77572f2a29c53d8a7ce8d9448579")
	// fmt.Println("sn:", sn.Hex())
	// r := common.HexToHash("0x706bb444aae459a509b5f694c1138c2d2a8b81802747e3d5989bb828fde50af1")
	// fmt.Println("r:", r.Hex())

	// cmtA_old := common.HexToHash("0x5481b30e41acc0611fcf055617c29247c776dbca03ea7a4566ee618b3a38319c")
	// fmt.Println("cmt_old:", cmtA_old.Hex())
	// cmtA := common.HexToHash("0xf9e4641a63b76a99306361826c26580e746c9f3f7756065cf789b97cf7f46385")
	// fmt.Println("cmt_new:", cmtA.Hex())
	// mint_proof := []byte("27d14db25a7c0b9f77ae129e9140257090c94e22f220b6d0098e0e3e16667d45236cef503e7b1d0b0f0c7c8eda970791909cfd1d1110fdddc9c845af769407a806673206678c9c367af3b63b47a357244f608cb89963de7b5bb24cda55f4735c2687ad2a7415b749d4deaed40e0c4191b1e49595246d0d66540e1e6fd19980f5180b26b0ce13fb715021bf559d9db47e9b88e0d7740b8327459f5f90083fc0ed1e1aa1a3856e05a85b167f6a848699291739a4c6ea7b94a406ea5866081d3a830c23d2e8a3e4d7015fc4aa124b4977168fef3b7de343f813421da915e02e327320996d88118b6f8586b08f3cc584d84bffd23b3e8ebf9693af6c7d900ca8daf926a27c07ab4627a2de1042e15f120d4ac2be2fd4d6629ec78c8a5d8db0d2ece2057a0f86c8ee377f3067ffbc4cbc95c1b367ac7b7c356e2fe82d8724ce9f2c8107e993f6889b099bfd2415ab1c991b9173ce692ed078d36820a22f5eba147c8a1f8f5f98103c71893d6646cbf4b20872c27d508467535cf530e847d65301bc5b0cb72065a5c5620e334b56bd05f3a6921ee3f40f6dafafeb8073aea9c053bacb29d95494a0c199457fd05a664e01404f7ae60ee2ec4e5f54ce501b60612be7ce28eba810257b39154e4c2363c7a25782ad0b1a200f9f4aada891d96e69b3cad119044691dde1346cf3c2b84811f622ec223cbfb4a99f93f79a30f415939e97221d29ee966dc7a01e0983e408597f153ff5476e612a44b77f3e8021db7ed1a57b262978745c58a8027b26db7a621fef48b0b765ad2420040aac07de6208dc839d")
	// fmt.Println("mint_proof:", string(mint_proof))

	// zktx.VerifyMintProof(&cmtA_old, &sn_old, &cmtA, 10000, mint_proof)

	// /*
	// *test convert
	//  */

	// values := uint64(1000)
	// sn_s := common.HexToHash("0x5d1c0fbf86236d396ff8dd7b9c326cfd1b421dbf12bd6d6933f5921a283360c2")
	// fmt.Println("sn_s:", sn_s.Hex())
	// r_s := common.HexToHash("0xcdcca9150ef5a38737e3f59ccda6f4b569ce13c7b691b0db1cd2327f2da5e384")
	// fmt.Println("r_s:", r_s.Hex())

	// //value_new := uint64(9000)
	// sn_new := common.HexToHash("0xc782038add929164795c2002ba28b02a0669b78ffbfe0bc0deafee97e4691392")
	// fmt.Println("sn:", sn_new.Hex())
	// r_new := common.HexToHash("0x3f023847309a25bf89ca757d3c12d39c15f2f11670e74efe9a17f304acecdb0d")
	// fmt.Println("r:", r_new.Hex())
	// cmtA_new := common.HexToHash("0x0f2d410bbbd9c1daf445cae124c8a4dcfe13fe2f67dd45eea6ac6d192e4bbee1")
	// fmt.Println("cmt_new:", cmtA_new.Hex())
	// cmtS := common.HexToHash("0x0dd5da0b3efc5a79f7f9a75fa1e02083f79360f3bbe979eda2d49f7c26bc1b5a")
	// fmt.Println("cmt_s:", cmtS.Hex())
	// convert_proof := []byte("13663c31dbbb44adbeb237d9c87f4598c9217110af9f211ff941543a16b03ece2c9163ac483b27e43304ea117921c4aee52b4a8a1a6186cb78b8c1d363a100bb2ad5a96d59c576da2cbd05a87ea19e03aa2f7a3020e179a61f3a84bd94732268217da158ed73246715eba1c09e0ff8c45a4aea3b948bb7788569ffe8578bca8d128b544166b0c44ff397e2f892a1b14f1e8fba22eb04e175a704078e8626ffef260d1f9a19a5b0ac2ec7f743efc6f110c6926c20acf155edb155e10471807daf2f20d27087d95c6fca683ad090f794d1e8b77872d0d0f31eb85fbb74b8bdf16528142a72013a7416517550c67d69d39f384b167a7035b4d028dbd3b17a8dc1340a57b2e85a3d32335856964d7bb8324e5b75a62bd4c3ce50a58a900557cdc30b020aa8b03e930e27e4946c0f8ae7d65892864d1201b8a81d8fd7f6e676c7a352036553b6b5c3b65aece1c0931dd56c092f2414eb2be1ff94f06517f27f3ec3a0231852558f1b91cdd163bd6a77204ab8292945c719f4f4624afbea486064868c2bc0cd721b670cdd55eb80a5ea13d8398fd70caa0f4f2f9f2cec1ef9b1bbe6df196a533466668050992377e142d6c519b76b6f13cdf5481c4c8819d823a7f9482d9edf660314fc17671940b54599237e9f7d68e2db325a2604a5965731daa54921c8852e0f7e718afeebb0dca99af7f69d403cfa237a911f272d312321ed9976289944c3e081f58feacd19ccb110efdc1dc2fe8172b7d8e59b072ac41333d5392c1daba49ebfce35beb80b9d6623a96e74b8fb89d7be918f43370a8e30a683a7")
	// fmt.Println("convert_proof:", string(convert_proof))
	// zktx.VerifyConvertProof(&sn, &cmtS, convert_proof, &cmtA, &cmtA_new)

	/*
	*test commit
	 */
	// values := uint64(100)
	// sn_s := zktx.NewRandomHash()
	// r_s := zktx.NewRandomHash()
	// snA := zktx.NewRandomHash()
	// cmtS := zktx.GenCMT_1(values, sn_s.Bytes(), r_s.Bytes(), snA.Bytes())

	// cmt_str := []string{"0xf1c5065347fbc8b09870327031cee307223e47f6b0635e8f31f148217c5d57e9",
	// 	"0x456eebc47c43b9af0f4f6c7b1d7093fa379931e0ef7170019eb58dee215d1f1d",
	// 	"0xed29100dbf744254e89e5396432cc20a3abe101e4853e33efd0edb0637189453",
	// 	"0xdfd71424f1153ab24a9995b05f4c9cbbde080055bf2774a69ba58a8be409f872",
	// 	"0x558841935e39af07d58b8cfe2a1b2ef92af119535bd44e9698a25adcaad1b4e3",
	// 	"0x35b08ba7feb31de2a64853548650ac7e6506642c76d36ccc95c50ca9b1d7f205",
	// 	"0x91e878c71a9b575080d6a5d525a5426876b83bc7e52f30937809bcb4024bc15a",
	// 	"0x4f60392c9b6f78b6181555aed80242b22170ac78397646bee1baa27f9f768197",
	// 	"0x13e4c77f676c91e806b499e2ef2bd16cd5438c39c3d87f2423d6e4a30fe2ef83",
	// 	"0x0dd5da0b3efc5a79f7f9a75fa1e02083f79360f3bbe979eda2d49f7c26bc1b5a",
	// 	"0x655550e8bd26504717a965c47f32f93bb0b0e002936b0b9d5e6583e6bd2fbd18",
	// 	"0xf844a59228ed5432c692ac4e895ff430df5e0e2c72e0a9c2b5d3dbccdfe54e3d",
	// 	"0x7c1c156ebf74633eb44b461178dc0d107db847b9710e313f4f5d2a816608c3ad",
	// 	"0x2f06ed56305c54117aa689018874b4bf478baefbf940c67bd19a18e9f023e0e6",
	// 	"0x919ecd9f9cc6d65f509b1823f65e47264e2212eefc198dedc0ede98026bdb7af",
	// 	"0xb55b09f47918b7da9faca6799b6ec37b89834f8410ee5ac41d831d94d4b4debd",
	// 	"0x413af06bb40c504eb3dd6df0834e92966ce095b5ea567be7ac0013973733e41f",
	// 	"0xe63180a113959e3d79e1089d6b13e69097f91d70834a1b237e7121548276caed",
	// 	"0xf90c0c7265b8741c48e5c88c5a62ae8654c11064816879ddaf33c6a9495a4e06",
	// 	"0x91fe621985723a0cf52c24171c6a75d4822e087a9d1834316a50154e55666c86",
	// 	"0x6b414f98c4a6bea1d19554b0312df5c9ee57436fdbabbb20ef5e50a12a38688f",
	// 	"0x2efd7d45e2a1afb305494ba6c5689b51577abf651d3f2a14dd027dba234314cd",
	// 	"0x172852c8fbc078fcb7f6538072c542c738b803d62b3f7d977d64a5096cc07c56",
	// 	"0x2ee2033ce2389e7fe22a454665d8a128f5cfc7a6f63cd8af862f76b817f8ada9",
	// 	"0x8c4b0ba5a2be9e5d0aa2cb957e0e12d8e761c03f3b37059220ce9d7a1f415fc5",
	// 	"0x9ad4707baa3a5ecc8b0d05f9ded057629a1037c96343ccfde596b3668e0ec1dd",
	// 	"0x83fd662d7ebed9cd307a6d981b19053822bf5115c571c2c18424e163bffe6258",
	// 	"0xd75e4b40b1599c3dc43bc6cf0770582ff7e7cd2b87ddf7720bb859238b967fcc",
	// 	"0x70f2fe589f31ed8d9b23d604d4f042425a1c06d598a70977454fb1e1b94f4e5d",
	// 	"0x3070f2e966ce43fb4b6128b43cb65b65be00df5af1e3af6f2bcbefc323772ffc",
	// 	"0xd2e7968ec0c91ac5e445e7c4b7a614f1898ee36753bdb1178a9be9bd9f743013",
	// 	"0xaadc0030c6e7106f79ff05419493d41fc52d6aa8eb922e6149c942e917459836"}

	// cmtarray := make([]*common.Hash, 32)
	// for i := 0; i < 32; i++ {
	// 	tmp := common.HexToHash(cmt_str[i])
	// 	cmtarray[i] = &tmp
	// }

	// RT := common.HexToHash("0x0af12fee60bd5b9edf75aa1fbac1b5b0fe06fab8537c5920dfcee7299dd08f15")
	// fmt.Println("RT:", RT.Hex())

	// commit_proof := []byte("182c94b81a78c0b49c564e88c9b050bc0aab3a4f06d1e32748b15d9efc4b74690a7adc09a0bcbf8d979f4221e51b2f9545629b69fb13b4644260191e80b2c92324556f494afd87fe14a88e645bfee04a7a31a357474b78f423418ef57c3db7111c01475cde0bee00b4b23a66201195645af50c1f775240ee1810c78d82262c1510944aa3a7cff95d3c144959596f1938b375281ebd1c19abfe8ddc9bd77045592e9dd3ec6186d6051382fc1ef53eadb81be51e5fcffc09ff3bf25a7a310c2e3926bfbe015aebc229eff495f9af39e1f81687ea19149b997ab3e8ac19047d1807022af3af9c1954948cfcf07becd5d244d613b33a638f3ae8b7f73d81622e4e9626e8b81e602792bfca6103c9d94ae6c47ccf3a5b176f8c2a1890862228fce65505f54132315def1c49dddc8ce25e0cbe7721fad1828707de56ed9f5f36a46292249a6e60f9d67087bbf3a5aa0ca0c06a508b981b511c223a2b28721a263bb8ca2fb75dd8c849d0a96a183e8480c1ed60150569cb81513bc403a05d9018b2b42a23cfa02e5fa6b953b6335acec58711aff8ad1300837888ad42e529d754f1be861303dc7e63a4e6fb9d39122b9af317ff224b8c26cc850aa20cd09df3826d159e283d84cfde735a269fca6300e7dc67c2a7ebbba4940dfdc4d60b7bc49786005e00072a38325ec8a170a5886fee24844ea033e5841879318488826a3c2e94b09013ee236cf0532a3bb21e0ca1dfb3f5027a13edeed9b478645a2b18d3304e951405195f8fa6c23b7ef8c8437b38733c313fe901225ef3c1c07bdf3c0fb0a733cf")
	// fmt.Println("commit_proof:", string(commit_proof))

	// zktx.VerifyCommitProof(values, &sn_s, RT.Bytes(), commit_proof)

	// // /*
	// // *test claim
	// //  */
	// v := uint64(50)
	// sn_v := common.HexToHash("0x482c99c2421dfbc8517ab8a2d971e365cd32f34eb37f17bd7af342b22790a6f4")
	// fmt.Println("sn_v:", sn_v.Hex())
	// r_v := common.HexToHash("0x3206e16b56b0f6f0d6bcd2ca5999bc93b3f57dd8932bb67ce5c47a4b3862e77c")
	// fmt.Println("r_v:", r_v.Hex())
	// cmtv := zktx.GenCMT(v, sn_v.Bytes(), r_v.Bytes())
	// fmt.Println("cmtv:", cmtv.Hex())

	// claim_proof := zktx.GenClaimProof(v, &sn_v, &r_v, cmtv)
	// fmt.Println("claim_proof:", string(claim_proof))

	// zktx.VerifyClaimProof(cmtv, v, claim_proof)

	// // /*
	// // *test Refund
	// //  */
	// v_r := uint64(950)
	// sn_r := common.HexToHash("0x5a8e160331744a86c408f152bc51c3637395faa5dbdd672beecdf85dc3ebcd1b")
	// fmt.Println("sn_v:", sn_r.Hex())
	// r_r := common.HexToHash("0xc9646ac65155b1326b5f94c2e1bdb19f2f34ecf950561e4a976785cc74450b77")
	// fmt.Println("r_v:", r_r.Hex())
	// cmtr := zktx.GenCMT(v_r, sn_r.Bytes(), r_r.Bytes())
	// fmt.Println("cmtv:", cmtr.Hex())

	// refund_proof := zktx.GenClaimProof(v_r, &sn_r, &r_r, cmtr)
	// fmt.Println("refund_proof:", string(refund_proof))
	// zktx.VerifyClaimProof(cmtr, v_r, refund_proof)

	/*
	*test deposit_sg
	 */

	//deposit B

	// v_old := uint64(0)
	// v_s := uint64(150)
	// v_new := v_old + v_s

	// sn_v_new := common.HexToHash("0x7792f54a0b68234ed2a8d3dfaf82ae6fd2b715d5997d0300f7f11b77d8a2c278")
	// fmt.Println("sn_v_new:", sn_v_new.Hex())
	// r_v_new := common.HexToHash("0xc0c7ea0dfd6de3183896bdca10dcd5b1881817f66d24b6ce18330018e4f21793")
	// fmt.Println("r_v_new:", r_v_new.Hex())
	// cmtB := common.HexToHash("0x1344f724ace5da092b3c6229a840c5b4e590172159808e6bf54bd6def2e42633")
	// fmt.Println("cmtB:", cmtB.Hex())

	// var cmtarray_1 []*common.Hash
	// for i := 0; i < 32; i++ {
	// 	if i == 9 {
	// 		cmtarray_1 = append(cmtarray_1, &cmtv)
	// 	} else {
	// 		cmt := common.HexToHash(cmt_str[i])
	// 		cmtarray_1 = append(cmtarray_1, &cmt)
	// 	}
	// }

	// RT_1 := common.HexToHash("0xad03b0ca053b4579f252b2ac7cf86c3f34a8b91b6b6495c882f0a53419979cd0")
	// fmt.Println("RT_1:", RT_1.Hex())

	// deposit_proof := []byte("1d748ae30c77d7ec4167132cd2066a5d3aca1a47e00b5ec1392bdb0bf733e24929a6066be14c343148115daccb4c7e96bba3dd1a5af40404c3615ea68d1f9bca094bb4e83c0833a67c19e98b1891d46cdb4a7853350edfe8a053ed2c3e1f2f81280c5fb9f89a808223ffb2db516b3a51f9d9ccc440d796a6cfa2027c3874046b0cb969f23de1c9dde3a883c1c3e8b52e0dcba2a133b2719a51512857b01a0b6f1f78857a75d1a34b3d30d2607874c9e969cc2f5d4689f4f11004e0df69ac6a45188e5501e54a1ab0dfaaa9166b328b72956d1567e4bebac164aa7fc1dedf3d270c09eb95c0392ca9a3e5738c0aad587cf3fecf22bcdf0f802326d0198accb1ca141a890507e0db178ee64a18070f26d6f5af178d9333bb0260c115a680c07dea15e24ba8220c0eb1bea6fe3fb953f6c25dc9edda8065e9e4a906c2ce8f8e3bfb29dca1868d4a05e1c699e4a1aa87caf739f27fb1364c516ed04aa5bea9c90d7c2c5b3c5fdf4ba429bed9421753ebade8ff3a7d6a7307edc9b3579cba8905e65a2be29c909787c906c6bb2bcb8b98468b54efa552023d6e82bb6ba4fdf38aeace14332634c9796129f327cd3b6574bb43155e6a8578babf18624d86784882c5ad1373fd22e7d5909e222e63a0b991a8274f16d1916003436d98a2a268c5f5afe70c5167af5992dda4613f2640ee0767c2b839a08c816e08a1182a07f97fcfc63f0721a4fdf35cd55012054dc9cedc5221aeda6bf815bdb3adb52b659db6eac8582d2b22f85f701e9d0dce25cc63e3fc45bac6d28e27dcc0961c7b7dbb478bd6ad")
	// //deposit_proof := zktx.GenDepositsgProof(&cmtv, v, &sn_v, &r_v, value_old, &r_old, &sn_v_new, &r_v_new, RT_1.Bytes(), &cmtA_old, &sn_old, &cmtB, cmtarray_1)
	// fmt.Println("deposit_proof:", string(deposit_proof))

	// zktx.VerifyDepositsgProof(&sn_v, RT_1, &cmtA_old, &sn_old, &cmtB, deposit_proof)

	//deposit A

	// v_old := uint64(9000)
	// v_s := uint64(850)
	// v_new := v_old + v_s
	// fmt.Println(v_new)
	// sn_v_new := common.HexToHash("0x7792f54a0b68234ed2a8d3dfaf82ae6fd2b715d5997d0300f7f11b77d8a2c278")
	// fmt.Println("sn_v_new:", sn_v_new.Hex())
	// sn_v_s := common.HexToHash("0xef7c718b3694c354bc1a6a03b257e0cfbe3159cb5eec5337d06ecd9dd3ea7e63")
	// fmt.Println("sn_v_s:", sn_v_s.Hex())
	// r_v_new := common.HexToHash("0xc0c7ea0dfd6de3183896bdca10dcd5b1881817f66d24b6ce18330018e4f21793")
	// fmt.Println("r_v_new:", r_v_new.Hex())
	// r_v_s := common.HexToHash("0x64e5357c9c90163cd98f45c1c069d8e5b8500307d37a6cff58a12cd86c7ef2f6")
	// fmt.Println("r_v_s:", r_v_s.Hex())
	// //old=cmtA_new
	// cmtB := common.HexToHash("0x86d72112136856ed290f5b7fd6e71b4c90a6a964470fb4ccdc2e7a5c0fdd4834")
	// fmt.Println("cmtB:", cmtB.Hex())
	// cmt_v := common.HexToHash("0xf6851b1946b3a2acb99939514eb32d3d2bfbb46614f473b4410fdeb5da2abbc6")
	// fmt.Println("cmt_v:", cmt_v.Hex())

	// var cmtarray_1 []*common.Hash
	// for i := 0; i < 32; i++ {
	// 	if i == 9 {
	// 		cmtarray_1 = append(cmtarray_1, &cmt_v)
	// 	} else {
	// 		cmt := common.HexToHash(cmt_str[i])
	// 		cmtarray_1 = append(cmtarray_1, &cmt)
	// 	}
	// }

	// RT_1 := common.HexToHash("0x04a10bf6323b86ae9f16b14cd2d068dea9693698e3d2e1b146848cdaac967c55")
	// fmt.Println("RT_1:", RT_1.Hex())

	// deposit_proof := []byte("261b93c699d6e4607052dd580d42259655440a142734bc2c064a2d268e9433eb27155e535bd34698eb27e15ca2446e461954f042517dc697139258e1a8a59313050ba1af3ba1bcebc0f8ec130d46bf1f526f8846bd0bebcf2ffa4e03dbad288215c6c48c5819aee61c14e81bc13facbca2461da51a1a2abcf4630153c676d30625cfa9058e4a7e3bd5bd713cc481862ae96baa6cee50d98835b3a2aa138b481005d3e1953969a139634998b659027612ae2debe526e95076a88c983f728e2a5c0e46a5b95d74c162e264962adac0224e51e88bdfb5a432103e8bcf2589719ae30ada8bc79d41e00a2e183f991e7fe624de84ae0b20099e37c919375e130fb9d92cdee5a93483d29bf221338649eee737c5140a70e9cedd84b7f12bc7a67f73d30d6783f49ce8b6eafae53a07aa75d718a257bb56700d39c727476a5e56722cc60ed90485a620dd713005bc4629848cfe71e60212f685b5c5895ed7f4d5dbf9b72536d4c09316393ac740e5a3ad0591991f3c8c1e250bf9d0346c51fb9c4670a1158648a802c39ecfc1094302a8986a1df925d4ff4b36dc77df64d1f000c1ccbc0d57af21495e668b341d90c07c07ab8e0add23b210b8ec9183959b454f2c507a0a651093b0f1bc29256b3bc8381cf2840ac553333b8853f968440d13e07388150138f666c4ae0a31b6df0c8c54da7a2de023dded49ee703552e967bc094f6f562f7e9e59aab9b3bf93a578dfb03a267f5e211f5f72a9d51c7e730cd664234c9b0430744d2eecf1470a2912b4eac6005f137cdd8ac8a92277ff5583e20a89e51b")
	// fmt.Println("deposit_proof:", string(deposit_proof))

	// zktx.VerifyDepositsgProof(&sn_v_s, RT_1, &cmtA_new, &sn_new, &cmtB, deposit_proof)

	// value_old := uint64(2000)
	// values := uint64(1000)
	// value := value_old + values

	// sn_old := zktx.NewRandomHash()
	// sn := zktx.NewRandomHash()
	// sn_s := zktx.NewRandomHash()

	// r_old := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()
	// r_s := zktx.NewRandomHash()

	// cmtB_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtB := zktx.GenCMT(value, sn.Bytes(), r.Bytes())
	// cmtS := zktx.GenCMT(values, sn_s.Bytes(), r_s.Bytes())
	// // cmtS_1 := zktx.NewRandomHash()

	// var cmtarray []*common.Hash
	// for i := 0; i < 32; i++ {
	// 	if i == 9 {
	// 		cmtarray = append(cmtarray, cmtS)
	// 	} else {
	// 		cmt := zktx.NewRandomHash()
	// 		cmtarray = append(cmtarray, cmt)
	// 	}
	// }

	// RT := zktx.GenRT(cmtarray)

	// proof := zktx.GenDepositsgProof(cmtS, values, sn_s, r_s, value_old, r_old, sn, r, RT.Bytes(), cmtB_old, sn_old, cmtB, cmtarray)

	// zktx.VerifyDepositsgProof(sn_s, RT, cmtB_old, sn_old, cmtB, proof)

	/*
	*test mint
	 */
	// value_old := uint64(1000)
	// value := uint64(2000)
	// value_m := value - value_old

	// sn_old := zktx.NewRandomHash()
	// sn := zktx.NewRandomHash()

	// r_old := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()

	// cmtA_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtA := zktx.GenCMT(value, sn.Bytes(), r.Bytes())

	// proof := zktx.GenMintProof(value_old,r_old,sn,r,cmtA_old,sn_old,cmtA,value)

	// zktx.VerifyMintProof(cmtA_old,sn_old,cmtA,value_m,proof)

	/*
	*test redeem
	 */
	// value_old := uint64(2000)
	// value := uint64(1000)
	// value_m := value_old - value

	// sn_old := zktx.NewRandomHash()
	// sn := zktx.NewRandomHash()

	// r_old := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()

	// cmtA_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtA := zktx.GenCMT(value, sn.Bytes(), r.Bytes())

	// proof := zktx.GenRedeemProof(value_old,r_old,sn,r,cmtA_old,sn_old,cmtA,value)

	// zktx.VerifyRedeemProof(cmtA_old,sn_old,cmtA,value_m,proof)

	//byte connect
	// i := []byte("asd")
	// j := []byte("fgh")
	// var buffer bytes.Buffer
	// buffer.Write(i)
	// buffer.Write(j)
	// fmt.Println(buffer.Bytes())

	//hash chain
	// hChain := GenHashChain(1000)
	// fmt.Println("h0:", hChain[0].Hex())
	// fmt.Println("hi:", hChain[50].Hex())
	// NumberOfHash(hChain[0], hChain[50], 1000)
	// t := time.Now()
	// fmt.Println(t.UTC())
	// f := fmt.Sprintf("%d:%d:%d.%d", t.Hour(), t.Minute(), t.Second(), t.Nanosecond())
	// fmt.Println(f)
	// data := []byte(f)
	// if ioutil.WriteFile("test.txt", data, 0644) == nil {
	// 	fmt.Println("写入文件成功:", f)
	// }

	endList := make([]bool, 10)
	fmt.Println(endList)
}

func NumberOfHash(root common.Hash, hi common.Hash, N uint64) uint64 {
	n := uint64(0)
	for h := hi.Bytes(); !bytes.Equal(h, root.Bytes()) && n <= N; n++ {
		h = crypto.Keccak256(h)
	}
	if n > N {
		fmt.Println("invaild hash")
		return 0
	}
	fmt.Println(n)
	return n
}

func GenHashChain(N uint64) []common.Hash {
	h_N := *zktx.NewRandomHash()
	hashList := make([]common.Hash, N+1)

	for n, h := (int)(N), h_N; n >= 0; n-- {
		hashList[n] = h
		h = crypto.Keccak256Hash(h.Bytes())
	}
	return hashList
}
