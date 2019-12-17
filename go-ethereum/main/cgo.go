package main

import (
	"bytes"
	"fmt"	
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

	//value := uint64(10000)
	sn := common.HexToHash("0xbdba1ea395c9bfc41f666440c1030e1d705f77572f2a29c53d8a7ce8d9448579")
	// fmt.Println("sn:", sn.Hex())
	//r := common.HexToHash("0x706bb444aae459a509b5f694c1138c2d2a8b81802747e3d5989bb828fde50af1")
	// fmt.Println("r:", r.Hex())

	// cmtA_old := common.HexToHash("0x5481b30e41acc0611fcf055617c29247c776dbca03ea7a4566ee618b3a38319c")
	// fmt.Println("cmt_old:", cmtA_old.Hex())	

	cmtA := common.HexToHash("0xf9e4641a63b76a99306361826c26580e746c9f3f7756065cf789b97cf7f46385")
	// fmt.Println("cmt_new:", cmtA.Hex())

	// //mint_proof := zktx.GenMintProof(value_old,&r_old, &sn, &r, &cmtA_old, &sn_old, &cmtA, value)
	// mint_proof := []byte("19b17abf3f3876ed49378fddaa026c148bba042e3834e2a73f4ad6bfbe088df60203ea3b66c308970621e574bc17468818c9d590670787ea0187d8c957f3f30014540f443bd963e32e7c20533527d53532f01c964d51b832ed8cfcb824f262610c5a10182387d2f043ca5b8e9c211d64708924cd9039ed372446e8f71a90c7a703015c4d022e6b235749d87361265be896023fd7e25ccca3d5d13fabbb1e2ffb25773a91c22cd20903d2913535263150ab5c89f0d5d5e80122697db30a1a33c515446a8ffe3ae311d4a15286eb247bfcf5149fcb476ba7ae34ffc371e60c0d2e1e7ad586b2d3675430f21c60de40d40c5fbafae88f98b6f894fd5a4ef9cc2baa0620247318d6929c2da136883daad5f708e0daf3165b02fb094c9461b7a20a1309e72435805d59d8df421a0eca2874c680309cd49ffbd617bfea963c2b6a93d82cbedc4f9a15bb65c3bc96dbd2345954f038a3cded52b10a73e68cb8a08c838e03c5824becc6c7bd42419ab8be15960bf57ebdebca07d18f73043e77c99ae89c23d87218abec65616d0c3abfd22b293d4a746b888569b809936517271cfa586a29830e1c20406f091c098d3911eafc9e6ed4e4444c444b3926f8b67c9aeb78c201b3ed6b210c3e164fc28a341b36b42ace9c881239c7e6b1432bda38fbbd0dfe1fc2f67581eee16909eb580786a5c49ad580e6dcce84067924ff61ce3e5dd1301a37f00087edb5c03e89a3d462fcf0d2bc1ab8590559f36215139676182fee412b8d60bc7014ee5e8e1ea01a2cbb9e3223196437cb68d28481220bafedeae08a")
	// fmt.Println("mint_proof:", string(mint_proof))

	// zktx.VerifyMintProof(&cmtA_old, &sn_old, &cmtA, 10000, mint_proof)

	// /*
	// *test convert
	//  */

	//values := uint64(1000)
	sn_s := common.HexToHash("0x5d1c0fbf86236d396ff8dd7b9c326cfd1b421dbf12bd6d6933f5921a283360c2")
	fmt.Println("sn_s:", sn_s.Hex())
	r_s := common.HexToHash("0xcdcca9150ef5a38737e3f59ccda6f4b569ce13c7b691b0db1cd2327f2da5e384")
	fmt.Println("r_s:", r_s.Hex())
	//cmtS := zktx.GenCMT(values, sn_s.Bytes(), r_s.Bytes())
	cmtS := common.HexToHash("0x1c15a7710d1baff53034d0b6c8f79114e295c85e51f0d152e1daa94780e2c99b")
	fmt.Println("cmt_s:", cmtS.Hex())
	//value_new := uint64(9000)
	sn_new := common.HexToHash("0xc782038add929164795c2002ba28b02a0669b78ffbfe0bc0deafee97e4691392")
	fmt.Println("sn:", sn_new.Hex())
	r_new := common.HexToHash("0x3f023847309a25bf89ca757d3c12d39c15f2f11670e74efe9a17f304acecdb0d")
	fmt.Println("r:", r_new.Hex())
	cmtA_new := common.HexToHash("0x0f2d410bbbd9c1daf445cae124c8a4dcfe13fe2f67dd45eea6ac6d192e4bbee1")
	fmt.Println("cmt_new:", cmtA_new.Hex())
	
	//convert_proof := zktx.GenConvertProof(&cmtA, value, &r, values, &sn_s, &r_s, &sn, cmtS, value_new, &sn_new, &r_new, &cmtA_new)
	convert_proof := []byte("23e3233322a634dd0167535d16053150be4f2421746088e10899cec46c90b4c80980c4de4a3326690cd895b821edb19d9b8971cdf61507c0f60efb39bddf45552a9c39a3bb67b9be9eeeb141e432060cb1e8e71d70c142d8868855f5d555723b2abc8328b0ae639c4ae9155bb62df70a78e3f5cef70a04d8e3161c083445a9b60e586bf73766aeef5bafec789b72fc1623716a55236ece0a6386347f06ddc23a1cc75604bd3480a656ae8bd084b2866ca700c29baec36a473a6da4e8712b2c9225e9196bb8861f7f14b20e006632f58f02e8466450e21dda8c044f2fdd6d29d50fe2c0060c6057af06357953b8be09f946a8a1902d476721a686789e96562aec1ebd934d31841d9e207b920741b668a5afe3f81f55acc17fb49852890f4f92fb0bdf99ddd4b210a7864ad49d8678720449a386c0d374af79275b1c2cd60c7ed62a0731e19007d23d8a7eff5c93b33e4871a603ae68c2cd9548790e01497b3ce025937f02ae1b664e4cb83daa03fedca4812b11fdea76243ecefd09507164e52518318f2936706aa2a6eaf04f3f2b56fc4184aa17e361b4174f011f390398518706515d94ddbff89337ef16aba20249905d3117eaaae25f6efa2a54246f6c5b37300dff2040a803426ef05a64ad0db8438143d658f6bb8364fe02c873a0921e422fc90fe13bab00f9c95255bc8790048644f7080959df2ac3448f3b53a37746a029fa84964330a564bd00458ffc290bb706c5bb3dd34e4b6d75b0c544434d6cd804313cf446ca717dde4652830f98166cea2577b214fd8401034334b04dbf65fd")
	fmt.Println("convert_proof:", string(convert_proof))
	zktx.VerifyConvertProof(&sn, &cmtS, convert_proof, &cmtA, &cmtA_new)

	/*
	*test commit
	 */
	//r_c := zktx.NewRandomHash()
	//r_c := common.HexToHash("0xcf33d584ecf0034fd749ddae0df8c58e16a387fa1078697c3bc0b67a6e889553")
	//fmt.Println("r_c:", r_c.Hex())
	//cmtC := zktx.GenCMT_1(values, r_c.Bytes())
	cmtC := common.HexToHash("0xd9bd22c7f6d35ddacad64374db2246bd42cf43f04fbe18647099d254fd6ad3e1")
	fmt.Println("cmtC:", cmtC.Hex())

	cmt_str := []string{"0xf1c5065347fbc8b09870327031cee307223e47f6b0635e8f31f148217c5d57e9",
		"0x456eebc47c43b9af0f4f6c7b1d7093fa379931e0ef7170019eb58dee215d1f1d",
		"0xed29100dbf744254e89e5396432cc20a3abe101e4853e33efd0edb0637189453",
		"0xdfd71424f1153ab24a9995b05f4c9cbbde080055bf2774a69ba58a8be409f872",
		"0x558841935e39af07d58b8cfe2a1b2ef92af119535bd44e9698a25adcaad1b4e3",
		"0x35b08ba7feb31de2a64853548650ac7e6506642c76d36ccc95c50ca9b1d7f205",
		"0x91e878c71a9b575080d6a5d525a5426876b83bc7e52f30937809bcb4024bc15a",
		"0x4f60392c9b6f78b6181555aed80242b22170ac78397646bee1baa27f9f768197",
		"0x13e4c77f676c91e806b499e2ef2bd16cd5438c39c3d87f2423d6e4a30fe2ef83",
		"0xccb9b61e2f98ad422dee8ad74448b2693e7663718fa8c33ae08ee6d561eda4d6",
		"0x655550e8bd26504717a965c47f32f93bb0b0e002936b0b9d5e6583e6bd2fbd18",
		"0xf844a59228ed5432c692ac4e895ff430df5e0e2c72e0a9c2b5d3dbccdfe54e3d",
		"0x7c1c156ebf74633eb44b461178dc0d107db847b9710e313f4f5d2a816608c3ad",
		"0x2f06ed56305c54117aa689018874b4bf478baefbf940c67bd19a18e9f023e0e6",
		"0x919ecd9f9cc6d65f509b1823f65e47264e2212eefc198dedc0ede98026bdb7af",
		"0xb55b09f47918b7da9faca6799b6ec37b89834f8410ee5ac41d831d94d4b4debd",
		"0x413af06bb40c504eb3dd6df0834e92966ce095b5ea567be7ac0013973733e41f",
		"0xe63180a113959e3d79e1089d6b13e69097f91d70834a1b237e7121548276caed",
		"0xf90c0c7265b8741c48e5c88c5a62ae8654c11064816879ddaf33c6a9495a4e06",
		"0x91fe621985723a0cf52c24171c6a75d4822e087a9d1834316a50154e55666c86",
		"0x6b414f98c4a6bea1d19554b0312df5c9ee57436fdbabbb20ef5e50a12a38688f",
		"0x2efd7d45e2a1afb305494ba6c5689b51577abf651d3f2a14dd027dba234314cd",
		"0x172852c8fbc078fcb7f6538072c542c738b803d62b3f7d977d64a5096cc07c56",
		"0x2ee2033ce2389e7fe22a454665d8a128f5cfc7a6f63cd8af862f76b817f8ada9",
		"0x8c4b0ba5a2be9e5d0aa2cb957e0e12d8e761c03f3b37059220ce9d7a1f415fc5",
		"0x9ad4707baa3a5ecc8b0d05f9ded057629a1037c96343ccfde596b3668e0ec1dd",
		"0x83fd662d7ebed9cd307a6d981b19053822bf5115c571c2c18424e163bffe6258",
		"0xd75e4b40b1599c3dc43bc6cf0770582ff7e7cd2b87ddf7720bb859238b967fcc",
		"0x70f2fe589f31ed8d9b23d604d4f042425a1c06d598a70977454fb1e1b94f4e5d",
		"0x3070f2e966ce43fb4b6128b43cb65b65be00df5af1e3af6f2bcbefc323772ffc",
		"0xd2e7968ec0c91ac5e445e7c4b7a614f1898ee36753bdb1178a9be9bd9f743013",
		"0xaadc0030c6e7106f79ff05419493d41fc52d6aa8eb922e6149c942e917459836"}

	cmtarray := make([]*common.Hash, 32)
	for i := 0; i < 32; i++ {
		if i==9 {
			cmtarray[i] = &cmtS
		}else{
			h := common.HexToHash(cmt_str[i])
			cmtarray[i] = &h
		}
	}

	//RT := zktx.GenRT(cmtarray)
	RT := common.HexToHash("0x549db31dd091837d7bb80b89d4bff28be9080011a18fe5773e7a2689912768ea")
	fmt.Println("RT:", RT.Hex())

	//commit_proof := zktx.GenCommitProof(values, &sn_s, &r_s, &cmtS, r_c, cmtC, RT.Bytes(), cmtarray)
	commit_proof := []byte("1dbe55723caec233620dd45167b3dcee117dab2bb2ae40c63a6a7f0f87b84a9e15cb7fcdb08fa0c3fd02ec2e4ba8db0046feb996afbbe25040625fad68ea5eb411e409cfef5f2b22048efd6f72e25b80bb30c7a1a93553e44fb8db7ee7756f120b6f383208319a4a88fda83d74481f7a7dec0c2fda26383dba270f8a2efb772601194fee11855e3635bde1b2f2bb227eb5d712faa2b92f6250c4712aaaa6338c1b1767db4e0d601ed02abea1e38ccd201899055dd8b9d9ffcc4e6a9b70bab3f61b2b20baa5542b7ca9d01e0f82c3bae66e9cdabb6385a458de771572d70beab202921435ee95f9e733f1a0f1b4961fea64cac346c81c07808171438ab9622be7077b6f50600ecdd1dea9dbd374ec59c14c99505d7c5af9f3d990768696388d7226ce845b5afc36d635fb94816698d0ab063d5d08837a168ce5804bbaaadde42926e8e2c3d6cffbadc0d6d8afaf185deaa10f9277c59bc678b6b4b1e0144f16a60b443851e438742f4de5daee08d75d12bce98582249f698e477d5e3cd142bc5d070b1c02a3b7656b44c1eac9921cd6321bff86b51a432396bc1e6a4f758ec47c21e8365cbc5251ea9a9eaace331e709a6c378184de8dc35ead6636354fe13fd520b0bdf94555aa40ac518595edfa378e560c6e6941803de91a15a8b492e63dd3217c478c38752d85347a5e2538fcbe304735e240f6096f43d5b525d37c6cc0ec260f99389c32b80d22d7ec9d495e6c2dd58538e8eff8ee2ff53aaf56414b555d00dbcf7fac9359bac0edbf316579323a071c7669f15659911c91b1d71a9b9f91")
	fmt.Println("commit_proof:", string(commit_proof))
	fmt.Println("verifying proof ......")
	zktx.VerifyCommitProof(&cmtC, &sn_s, RT.Bytes(), commit_proof)

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