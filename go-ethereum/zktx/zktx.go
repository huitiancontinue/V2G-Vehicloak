package zktx

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_mint -lzk_redeem -lzk_convert -lzk_commit -lzk_claim -lzk_deposit_sg -lff  -lsnark -lstdc++  -lgmp -lgmpxx


#include "mintcgo.hpp"
#include "redeemcgo.hpp"
#include "convertcgo.hpp"
#include "commitcgo.hpp"
#include "claimcgo.hpp"
#include "deposit_sgcgo.hpp"

#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Sequence struct {
	SN     *common.Hash
	CMT    *common.Hash
	Random *common.Hash
	Value  uint64
	Valid  bool
	Lock   sync.Mutex
}

type WriteSn struct {
	SNumber      *Sequence
	SNumberAfter *Sequence
}
type SequenceS struct {
	Suquence1 Sequence
	Suquence2 Sequence
	SNS       *Sequence
	PKBX      *big.Int
	PKBY      *big.Int
	Stage     uint8
}

const (
	Origin = iota
	Mint
	Send
	Update
	Deposit
	Redeem
	Convert
	Commit
	Claim
	Depositsg
)

var SNfile *os.File
var FileLine uint8

var Stage uint8
var SequenceNumber = InitializeSN()                //--zy
var SequenceNumberAfter *Sequence = InitializeSN() //--zy
var SNS *Sequence = nil
var ZKTxAddress = common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff")

var ZKCMTNODES = 1 // max is 32  because of merkle leaves in libnsark is 32

var ErrSequence = errors.New("invalid sequence")
var RandomReceiverPK *ecdsa.PublicKey = nil

func InitializeSN() *Sequence {
	sn := &common.Hash{}
	r := &common.Hash{}
	cmt := GenCMT(0, sn.Bytes(), r.Bytes())
	return &Sequence{
		SN:     sn,
		CMT:    cmt,
		Random: r,
		Value:  0,
	}
}

func NewRandomHash() *common.Hash {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	hash := common.BytesToHash(uuid)
	return &hash
}

func NewRandomAddress() *common.Address {
	uuid := make([]byte, 20)
	io.ReadFull(rand.Reader, uuid)
	addr := common.BytesToAddress(uuid)
	return &addr
}

func NewRandomInt() *big.Int {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	r := big.NewInt(0)
	r.SetBytes(uuid)
	return r
}

func VerifyDepositSIG(x *big.Int, y *big.Int, sig []byte) error {
	return nil
}

//GenCMT生成CMT 调用c的sha256函数  （go的sha256函数与c有一些区别）
func GenCMT(value uint64, sn []byte, r []byte) *common.Hash {
	//sn_old_c := C.CString(common.ToHex(SNold[:]))
	value_c := C.ulong(value)
	sn_string := common.ToHex(sn[:])
	sn_c := C.CString(sn_string)
	defer C.free(unsafe.Pointer(sn_c))
	r_string := common.ToHex(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))

	cmtA_c := C.genCMT(value_c, sn_c, r_c)
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

//GenCMT生成CMT 调用c的sha256函数  （go的sha256函数与c有一些区别）
// func GenCMTS(values uint64, pk *ecdsa.PublicKey, sns []byte, rs []byte, sna []byte) *common.Hash {

// 	values_c := C.ulong(values)
// 	PK := crypto.PubkeyToAddress(*pk) //--zy
// 	pk_c := C.CString(common.ToHex(PK[:]))
// 	sns_string := common.ToHex(sns[:])
// 	sns_c := C.CString(sns_string)
// 	defer C.free(unsafe.Pointer(sns_c))
// 	rs_string := common.ToHex(rs[:])
// 	rs_c := C.CString(rs_string)
// 	defer C.free(unsafe.Pointer(rs_c))
// 	sna_string := common.ToHex(sna[:])
// 	sna_c := C.CString(sna_string)
// 	defer C.free(unsafe.Pointer(sna_c))
// 	//uint64_t value_s,char* pk_string,char* sn_s_string,char* r_s_string,char *sn_old_string
// 	cmtA_c := C.genCMTS(values_c, pk_c, sns_c, rs_c, sna_c) //64长度16进制数
// 	cmtA_go := C.GoString(cmtA_c)
// 	//res := []byte(cmtA_go)
// 	res, _ := hex.DecodeString(cmtA_go)
// 	reshash := common.BytesToHash(res) //32长度byte数组
// 	return &reshash
// }

func GenCMT_1(values uint64, sns []byte, rs []byte, sna []byte) *common.Hash {

	values_c := C.ulong(values)
	sns_string := common.ToHex(sns[:])
	sns_c := C.CString(sns_string)
	defer C.free(unsafe.Pointer(sns_c))
	rs_string := common.ToHex(rs[:])
	rs_c := C.CString(rs_string)
	defer C.free(unsafe.Pointer(rs_c))
	sna_string := common.ToHex(sna[:])
	sna_c := C.CString(sna_string)
	defer C.free(unsafe.Pointer(sna_c))
	//uint64_t value_s,char* sn_s_string,char* r_s_string,char *sn_old_string
	cmtA_c := C.genCMT_1(values_c, sns_c, rs_c, sna_c) //64长度16进制数
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res) //32长度byte数组
	return &reshash
}

//GenRT 返回merkel树的hash  --zy
func GenRT(CMTSForMerkle []*common.Hash) common.Hash {
	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	rtC := C.genRoot(cmtsM, C.int(len(CMTSForMerkle))) //--zy
	rtGo := C.GoString(rtC)

	res, _ := hex.DecodeString(rtGo)   //返回32长度 []byte  一个byte代表两位16进制数
	reshash := common.BytesToHash(res) //32长度byte数组
	return reshash
}

func ComputeR(sk *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{} //tbd
}

func Encrypt(pub *ecdsa.PublicKey, m []byte) ([]byte, error) {
	P := ecies.ImportECDSAPublic(pub)
	ke := P.X.Bytes()
	ke = ke[:16]
	ct, err := ecies.SymEncrypt(rand.Reader, P.Params, ke, m)

	return ct, err
}

func Decrypt(pub *ecdsa.PublicKey, ct []byte) ([]byte, error) {
	P := ecies.ImportECDSAPublic(pub)
	ke := P.X.Bytes()
	ke = ke[:16]
	m, err := ecies.SymDecrypt(P.Params, ke, ct)
	return m, err
}

type AUX struct {
	Value uint64
	SNs   *common.Hash
	Rs    *common.Hash
	SNa   *common.Hash
}

func ComputeAUX(randomReceiverPK *ecdsa.PublicKey, value uint64, SNs *common.Hash, Rs *common.Hash, SNa *common.Hash) []byte {
	aux := AUX{
		Value: value,
		SNs:   SNs,
		Rs:    Rs,
		SNa:   SNa,
	}
	bytes, _ := rlp.EncodeToBytes(aux)
	encbytes, _ := Encrypt(randomReceiverPK, bytes)
	return encbytes
}

func DecAUX(key *ecdsa.PublicKey, data []byte) (uint64, *common.Hash, *common.Hash, *common.Hash) {
	decdata, _ := Decrypt(key, data)
	aux := AUX{}
	r := bytes.NewReader(decdata)

	s := rlp.NewStream(r, 128)
	if err := s.Decode(&aux); err != nil {
		fmt.Println("Decode aux error: ", err)
		return 0, nil, nil, nil
	}
	return aux.Value, aux.SNs, aux.Rs, aux.SNa
}

func GenerateKeyForRandomB(R *ecdsa.PublicKey, kB *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	//skB*R
	c := kB.PublicKey.Curve
	tx, ty := c.ScalarMult(R.X, R.Y, kB.D.Bytes())
	tmp := tx.Bytes()
	tmp = append(tmp, ty.Bytes()...)

	//生成hash值H(skB*R)
	h := sha256.New()
	h.Write([]byte(tmp))
	bs := h.Sum(nil)
	bs[0] = bs[0] % 128
	i := new(big.Int)
	i = i.SetBytes(bs)

	//生成公钥
	sx, sy := c.ScalarBaseMult(bs)
	sskB := new(ecdsa.PrivateKey)
	sskB.PublicKey.X, sskB.PublicKey.Y = c.Add(sx, sy, kB.PublicKey.X, kB.PublicKey.Y)
	sskB.Curve = c
	//生成私钥
	sskB.D = i.Add(i, kB.D)
	return sskB
}

func GenR() *ecdsa.PrivateKey {
	Ka, err := crypto.GenerateKey()
	if err != nil {
		return nil
	}
	return Ka
}

func NewRandomPubKey(sA *big.Int, pkB ecdsa.PublicKey) *ecdsa.PublicKey {
	//sA*pkB
	c := pkB.Curve
	tx, ty := c.ScalarMult(pkB.X, pkB.Y, sA.Bytes())
	tmp := tx.Bytes()
	tmp = append(tmp, ty.Bytes()...)

	//生成hash值H(sA*pkB)
	h := sha256.New()
	h.Write([]byte(tmp))
	bs := h.Sum(nil)
	bs[0] = bs[0] % 128

	//生成用于加密的公钥H(sA*pkB)P+pkB
	sx, sy := c.ScalarBaseMult(bs)
	spkB := new(ecdsa.PublicKey)
	spkB.X, spkB.Y = c.Add(sx, sy, pkB.X, pkB.Y)
	spkB.Curve = c
	return spkB
}

//V2G

func GenMintProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64) []byte {
	value_c := C.ulong(ValueNew)     //转换后零知识余额对应的明文余额
	value_old_c := C.ulong(ValueOld) //转换前零知识余额对应的明文余额

	sn_old_c := C.CString(common.ToHex(SNold[:]))
	r_old_c := C.CString(common.ToHex(RAold[:]))
	sn_c := C.CString(common.ToHex(SNAnew[:]))
	r_c := C.CString(common.ToHex(RAnew[:]))

	cmtA_old_c := C.CString(common.ToHex(CMTold[:])) //对于CMT  需要将每一个byte拆为两个16进制字符
	cmtA_c := C.CString(common.ToHex(CMTnew[:]))

	value_s_c := C.ulong(ValueNew - ValueOld) //需要被转换的明文余额
	t1 := time.Now()
	cproof := C.genMintproof(value_c, value_old_c, sn_old_c, r_old_c, sn_c, r_c, cmtA_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	genMintproof_time := t2.Sub(t1)
	log.Info("---------------------------------genMintproof_time---------------------------------")
	log.Info(fmt.Sprintf("genMintproof_time = %v ", genMintproof_time))

	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidMintProof = errors.New("Verifying mint proof failed!!!")

func VerifyMintProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(common.ToHex(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)
	t1 := time.Now()
	tf := C.verifyMintproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	veriftMintproof_time := t2.Sub(t1)
	log.Info("---------------------------------veriftMintproof_time---------------------------------")
	log.Info(fmt.Sprintf("veriftMintproof_time = %v ", veriftMintproof_time))
	if tf == false {
		return InvalidMintProof
	}
	return nil
}

func GenRedeemProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64) []byte {
	value_c := C.ulong(ValueNew)     //转换后零知识余额对应的明文余额
	value_old_c := C.ulong(ValueOld) //转换前零知识余额对应的明文余额

	sn_old_c := C.CString(common.ToHex(SNold.Bytes()[:]))
	r_old_c := C.CString(common.ToHex(RAold.Bytes()[:]))
	sn_c := C.CString(common.ToHex(SNAnew.Bytes()[:]))
	r_c := C.CString(common.ToHex(RAnew.Bytes()[:]))

	cmtA_old_c := C.CString(common.ToHex(CMTold[:])) //对于CMT  需要将每一个byte拆为两个16进制字符
	cmtA_c := C.CString(common.ToHex(CMTnew[:]))

	value_s_c := C.ulong(ValueOld - ValueNew) //需要被转换的明文余额
	t1 := time.Now()
	cproof := C.genRedeemproof(value_c, value_old_c, sn_old_c, r_old_c, sn_c, r_c, cmtA_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	genRedeemproof_time := t2.Sub(t1)
	log.Info("---------------------------------genRedeemproof_time---------------------------------")
	log.Info(fmt.Sprintf("genRedeemproof_time = %v ", genRedeemproof_time))

	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidRedeemProof = errors.New("Verifying redeem proof failed!!!")

func VerifyRedeemProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(common.ToHex(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)
	t1 := time.Now()
	tf := C.verifyRedeemproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	veriftRedeemproof_time := t2.Sub(t1)
	log.Info("---------------------------------veriftRedeemproof_time---------------------------------")
	log.Info(fmt.Sprintf("veriftRedeemproof_time = %v ", veriftRedeemproof_time))
	if tf == false {
		return InvalidRedeemProof
	}
	return nil
}

func GenConvertProof(CMTA *common.Hash, ValueA uint64, RA *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash, ValueAnew uint64, SNAnew *common.Hash, RAnew *common.Hash, CMTAnew *common.Hash) []byte {
	cmtA_c := C.CString(common.ToHex(CMTA[:]))
	valueA_c := C.ulong(ValueA)
	rA_c := C.CString(common.ToHex(RA.Bytes()[:]))
	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	snA := C.CString(common.ToHex(SNA.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	valueANew_c := C.ulong(ValueAnew)
	snAnew_c := C.CString(common.ToHex(SNAnew.Bytes()[:]))
	rAnew_c := C.CString(common.ToHex(RAnew.Bytes()[:]))
	cmtAnew_c := C.CString(common.ToHex(CMTAnew[:]))
	t1 := time.Now()
	cproof := C.genConvertproof(valueA_c, snS, rS, snA, rA_c, cmtS, cmtA_c, valueS, valueANew_c, snAnew_c, rAnew_c, cmtAnew_c)
	t2 := time.Now()
	genConvertproof_time := t2.Sub(t1)
	log.Info("---------------------------------genConvertproof_time---------------------------------")
	log.Info(fmt.Sprintf("genConvertproof_time = %v ", genConvertproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidConvertProof = errors.New("Verifying convert proof failed!!!")

func VerifyConvertProof(sna *common.Hash, cmts *common.Hash, proof []byte, cmtAold *common.Hash, cmtAnew *common.Hash) error {
	cproof := C.CString(string(proof))
	snAold_c := C.CString(common.ToHex(sna.Bytes()[:]))
	cmtS := C.CString(common.ToHex(cmts[:]))
	cmtAold_c := C.CString(common.ToHex(cmtAold[:]))
	cmtAnew_c := C.CString(common.ToHex(cmtAnew[:]))
	t1 := time.Now()
	tf := C.verifyConvertproof(cproof, cmtAold_c, snAold_c, cmtS, cmtAnew_c)
	t2 := time.Now()
	verifyConvertproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyConvertproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyConvertproof_time = %v ", verifyConvertproof_time))
	if tf == false {
		return InvalidConvertProof
	}
	return nil
}

func GenCommitProof(ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash, RT []byte, CMTSForMerkle []*common.Hash) []byte {

	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	snA := C.CString(common.ToHex(SNA.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	rt := C.CString(common.ToHex(RT))

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))
	t1 := time.Now()
	cproof := C.genCommitproof(snS, rS, snA, valueS, cmtS, cmtsM, nC, rt)
	t2 := time.Now()
	genCommitproof_time := t2.Sub(t1)
	log.Info("---------------------------------genCommitproof_time---------------------------------")
	log.Info(fmt.Sprintf("genCommitproof_time = %v ", genCommitproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidCommitProof = errors.New("Verifying commit proof failed!!!")

func VerifyCommitProof(ValueS uint64, SN_S *common.Hash, RT []byte, proof []byte) error {
	cproof := C.CString(string(proof))
	defer C.free(unsafe.Pointer(cproof))
	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SN_S[:]))
	defer C.free(unsafe.Pointer(snS))
	rt := C.CString(common.ToHex(RT))
	defer C.free(unsafe.Pointer(rt))
	t1 := time.Now()
	tf := C.verifyCommitproof(cproof, rt, snS, valueS)
	t2 := time.Now()
	verifyCommitproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyCommitproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyCommitproof_time = %v ", verifyCommitproof_time))
	if tf == false {
		return InvalidCommitProof
	}
	return nil
}

func GenClaimProof(ValueS uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash) []byte {

	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	defer C.free(unsafe.Pointer(snS))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	defer C.free(unsafe.Pointer(rS))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	defer C.free(unsafe.Pointer(cmtS))
	t1 := time.Now()
	cproof := C.genClaimproof(snS, rS, cmtS, valueS)
	t2 := time.Now()
	genClaimRefundproof_time := t2.Sub(t1)
	log.Info("---------------------------------genClaimRefundproof_time---------------------------------")
	log.Info(fmt.Sprintf("genClaimRefundproof_time = %v ", genClaimRefundproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidClaimProof = errors.New("Verifying claim proof failed!!!")

func VerifyClaimProof(cmts *common.Hash, ValueS uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	defer C.free(unsafe.Pointer(cproof))
	valueS := C.ulong(ValueS)
	cmtS := C.CString(common.ToHex(cmts[:]))
	defer C.free(unsafe.Pointer(cmtS))
	t1 := time.Now()
	tf := C.verifyClaimproof(cproof, cmtS, valueS)
	t2 := time.Now()
	verifyClaimRefundproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyClaimRefundproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyClaimRefundproof_time = %v ", verifyClaimRefundproof_time))
	if tf == false {
		return InvalidClaimProof
	}
	return nil
}

func GenDepositsgProof(CMTS *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, ValueB uint64, RB *common.Hash, SNBnew *common.Hash, RBnew *common.Hash, RTcmt []byte, CMTB *common.Hash, SNB *common.Hash, CMTBnew *common.Hash, CMTSForMerkle []*common.Hash) []byte {
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	valueS_c := C.ulong(ValueS)
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:])) //--zy
	RS_c := C.CString(common.ToHex(RS.Bytes()[:]))   //--zy
	valueB_c := C.ulong(ValueB)
	RB_c := C.CString(common.ToHex(RB.Bytes()[:])) //rA_c := C.CString(string(RA.Bytes()[:]))
	SNB_c := C.CString(common.ToHex(SNB.Bytes()[:]))
	SNBnew_c := C.CString(common.ToHex(SNBnew.Bytes()[:]))
	RBnew_c := C.CString(common.ToHex(RBnew.Bytes()[:]))
	cmtB_c := C.CString(common.ToHex(CMTB[:]))
	RT_c := C.CString(common.ToHex(RTcmt)) //--zy   rt

	cmtBnew_c := C.CString(common.ToHex(CMTBnew[:]))
	valueBNew_c := C.ulong(ValueB + ValueS)

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))
	t1 := time.Now()
	cproof := C.genDepositsgproof(valueBNew_c, valueB_c, SNB_c, RB_c, SNBnew_c, RBnew_c, SNS_c, RS_c, cmtB_c, cmtBnew_c, valueS_c, cmtS_c, cmtsM, nC, RT_c)
	t2 := time.Now()
	genDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------genDepositsgproof_time---------------------------------")
	log.Info(fmt.Sprintf("genDepositsgproof_time = %v ", genDepositsgproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDepositsgProof = errors.New("Verifying Deposit_sg proof failed!!!")

func VerifyDepositsgProof(sns *common.Hash, rtcmt common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {
	SNS_c := C.CString(common.ToHex(sns.Bytes()[:]))
	defer C.free(unsafe.Pointer(SNS_c))
	cproof := C.CString(string(proof))
	defer C.free(unsafe.Pointer(cproof))
	rtmCmt := C.CString(common.ToHex(rtcmt[:]))
	defer C.free(unsafe.Pointer(rtmCmt))
	cmtB := C.CString(common.ToHex(cmtb[:]))
	defer C.free(unsafe.Pointer(cmtB))
	cmtBnew := C.CString(common.ToHex(cmtbnew[:]))
	defer C.free(unsafe.Pointer(cmtBnew))
	SNB_c := C.CString(common.ToHex(snb.Bytes()[:]))
	defer C.free(unsafe.Pointer(SNB_c))
	t1 := time.Now()
	tf := C.verifyDepositsgproof(cproof, rtmCmt, SNS_c, cmtB, SNB_c, cmtBnew)
	t2 := time.Now()
	verifyDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyDepositsgproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyDepositsgproof_time = %v ", verifyDepositsgproof_time))
	if tf == false {
		return InvalidDepositsgProof
	}
	return nil
}

//---------data for test------------------

//初始化余额cmt
var CmtA_old = common.HexToHash("0x5481b30e41acc0611fcf055617c29247c776dbca03ea7a4566ee618b3a38319c")

var Sn_old = common.HexToHash("0x364d3f5af0cc140746b48072ff1ba28c12d84106bdcdf66e7a26c68f70e5f04c")

var R_old = common.HexToHash("0x80f10f96535550f7be47e0f7477ddec9d2d94b0df3bff810a97f9fd383104d3f")

//mint更新后余额
var CmtA = common.HexToHash("0xf9e4641a63b76a99306361826c26580e746c9f3f7756065cf789b97cf7f46385")

var Sn = common.HexToHash("0xbdba1ea395c9bfc41f666440c1030e1d705f77572f2a29c53d8a7ce8d9448579")

var R = common.HexToHash("0x706bb444aae459a509b5f694c1138c2d2a8b81802747e3d5989bb828fde50af1")

var Mint_proof = []byte("27d14db25a7c0b9f77ae129e9140257090c94e22f220b6d0098e0e3e16667d45236cef503e7b1d0b0f0c7c8eda970791909cfd1d1110fdddc9c845af769407a806673206678c9c367af3b63b47a357244f608cb89963de7b5bb24cda55f4735c2687ad2a7415b749d4deaed40e0c4191b1e49595246d0d66540e1e6fd19980f5180b26b0ce13fb715021bf559d9db47e9b88e0d7740b8327459f5f90083fc0ed1e1aa1a3856e05a85b167f6a848699291739a4c6ea7b94a406ea5866081d3a830c23d2e8a3e4d7015fc4aa124b4977168fef3b7de343f813421da915e02e327320996d88118b6f8586b08f3cc584d84bffd23b3e8ebf9693af6c7d900ca8daf926a27c07ab4627a2de1042e15f120d4ac2be2fd4d6629ec78c8a5d8db0d2ece2057a0f86c8ee377f3067ffbc4cbc95c1b367ac7b7c356e2fe82d8724ce9f2c8107e993f6889b099bfd2415ab1c991b9173ce692ed078d36820a22f5eba147c8a1f8f5f98103c71893d6646cbf4b20872c27d508467535cf530e847d65301bc5b0cb72065a5c5620e334b56bd05f3a6921ee3f40f6dafafeb8073aea9c053bacb29d95494a0c199457fd05a664e01404f7ae60ee2ec4e5f54ce501b60612be7ce28eba810257b39154e4c2363c7a25782ad0b1a200f9f4aada891d96e69b3cad119044691dde1346cf3c2b84811f622ec223cbfb4a99f93f79a30f415939e97221d29ee966dc7a01e0983e408597f153ff5476e612a44b77f3e8021db7ed1a57b262978745c58a8027b26db7a621fef48b0b765ad2420040aac07de6208dc839d")

//convert转账金额
var CmtS = common.HexToHash("0x0dd5da0b3efc5a79f7f9a75fa1e02083f79360f3bbe979eda2d49f7c26bc1b5a")

var Sn_s = common.HexToHash("0x5d1c0fbf86236d396ff8dd7b9c326cfd1b421dbf12bd6d6933f5921a283360c2")

var R_s = common.HexToHash("0xcdcca9150ef5a38737e3f59ccda6f4b569ce13c7b691b0db1cd2327f2da5e384")

var Sn_new = common.HexToHash("0xc782038add929164795c2002ba28b02a0669b78ffbfe0bc0deafee97e4691392")

var R_new = common.HexToHash("0x3f023847309a25bf89ca757d3c12d39c15f2f11670e74efe9a17f304acecdb0d")

//convert更新后金额
var CmtA_new = common.HexToHash("0x0f2d410bbbd9c1daf445cae124c8a4dcfe13fe2f67dd45eea6ac6d192e4bbee1")

var Convert_proof = []byte("13663c31dbbb44adbeb237d9c87f4598c9217110af9f211ff941543a16b03ece2c9163ac483b27e43304ea117921c4aee52b4a8a1a6186cb78b8c1d363a100bb2ad5a96d59c576da2cbd05a87ea19e03aa2f7a3020e179a61f3a84bd94732268217da158ed73246715eba1c09e0ff8c45a4aea3b948bb7788569ffe8578bca8d128b544166b0c44ff397e2f892a1b14f1e8fba22eb04e175a704078e8626ffef260d1f9a19a5b0ac2ec7f743efc6f110c6926c20acf155edb155e10471807daf2f20d27087d95c6fca683ad090f794d1e8b77872d0d0f31eb85fbb74b8bdf16528142a72013a7416517550c67d69d39f384b167a7035b4d028dbd3b17a8dc1340a57b2e85a3d32335856964d7bb8324e5b75a62bd4c3ce50a58a900557cdc30b020aa8b03e930e27e4946c0f8ae7d65892864d1201b8a81d8fd7f6e676c7a352036553b6b5c3b65aece1c0931dd56c092f2414eb2be1ff94f06517f27f3ec3a0231852558f1b91cdd163bd6a77204ab8292945c719f4f4624afbea486064868c2bc0cd721b670cdd55eb80a5ea13d8398fd70caa0f4f2f9f2cec1ef9b1bbe6df196a533466668050992377e142d6c519b76b6f13cdf5481c4c8819d823a7f9482d9edf660314fc17671940b54599237e9f7d68e2db325a2604a5965731daa54921c8852e0f7e718afeebb0dca99af7f69d403cfa237a911f272d312321ed9976289944c3e081f58feacd19ccb110efdc1dc2fe8172b7d8e59b072ac41333d5392c1daba49ebfce35beb80b9d6623a96e74b8fb89d7be918f43370a8e30a683a7")

//默克尔树数组
var Cmt_str = []string{"0xf1c5065347fbc8b09870327031cee307223e47f6b0635e8f31f148217c5d57e9",
	"0x456eebc47c43b9af0f4f6c7b1d7093fa379931e0ef7170019eb58dee215d1f1d",
	"0xed29100dbf744254e89e5396432cc20a3abe101e4853e33efd0edb0637189453",
	"0xdfd71424f1153ab24a9995b05f4c9cbbde080055bf2774a69ba58a8be409f872",
	"0x558841935e39af07d58b8cfe2a1b2ef92af119535bd44e9698a25adcaad1b4e3",
	"0x35b08ba7feb31de2a64853548650ac7e6506642c76d36ccc95c50ca9b1d7f205",
	"0x91e878c71a9b575080d6a5d525a5426876b83bc7e52f30937809bcb4024bc15a",
	"0x4f60392c9b6f78b6181555aed80242b22170ac78397646bee1baa27f9f768197",
	"0x13e4c77f676c91e806b499e2ef2bd16cd5438c39c3d87f2423d6e4a30fe2ef83",
	"0x0dd5da0b3efc5a79f7f9a75fa1e02083f79360f3bbe979eda2d49f7c26bc1b5a",
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

//commit rtcmt
var RT = common.HexToHash("0x0af12fee60bd5b9edf75aa1fbac1b5b0fe06fab8537c5920dfcee7299dd08f15")

var Commit_proof = []byte("182c94b81a78c0b49c564e88c9b050bc0aab3a4f06d1e32748b15d9efc4b74690a7adc09a0bcbf8d979f4221e51b2f9545629b69fb13b4644260191e80b2c92324556f494afd87fe14a88e645bfee04a7a31a357474b78f423418ef57c3db7111c01475cde0bee00b4b23a66201195645af50c1f775240ee1810c78d82262c1510944aa3a7cff95d3c144959596f1938b375281ebd1c19abfe8ddc9bd77045592e9dd3ec6186d6051382fc1ef53eadb81be51e5fcffc09ff3bf25a7a310c2e3926bfbe015aebc229eff495f9af39e1f81687ea19149b997ab3e8ac19047d1807022af3af9c1954948cfcf07becd5d244d613b33a638f3ae8b7f73d81622e4e9626e8b81e602792bfca6103c9d94ae6c47ccf3a5b176f8c2a1890862228fce65505f54132315def1c49dddc8ce25e0cbe7721fad1828707de56ed9f5f36a46292249a6e60f9d67087bbf3a5aa0ca0c06a508b981b511c223a2b28721a263bb8ca2fb75dd8c849d0a96a183e8480c1ed60150569cb81513bc403a05d9018b2b42a23cfa02e5fa6b953b6335acec58711aff8ad1300837888ad42e529d754f1be861303dc7e63a4e6fb9d39122b9af317ff224b8c26cc850aa20cd09df3826d159e283d84cfde735a269fca6300e7dc67c2a7ebbba4940dfdc4d60b7bc49786005e00072a38325ec8a170a5886fee24844ea033e5841879318488826a3c2e94b09013ee236cf0532a3bb21e0ca1dfb3f5027a13edeed9b478645a2b18d3304e951405195f8fa6c23b7ef8c8437b38733c313fe901225ef3c1c07bdf3c0fb0a733cf")

var Sn_v = common.HexToHash("0x482c99c2421dfbc8517ab8a2d971e365cd32f34eb37f17bd7af342b22790a6f4")

var R_v = common.HexToHash("0x3206e16b56b0f6f0d6bcd2ca5999bc93b3f57dd8932bb67ce5c47a4b3862e77c")

//claim转账金额
var Cmtv = common.HexToHash("0x08b90f281509a8961b943c74b87c0547c9164b729849f22d9b12ad5d799e2c49")

var Claim_proof = []byte("235f9a0f4645a932166efd406f7735477fccb1719562513c96203954cbd4199f1115c7952b6fd6cc5b7c50a853e11a773e9c3e706bd8e22da5cbf0859fa47495198838f0f11ab22573e5ab6ecd1fee34b0305e7eb4ee1580a3732c6dcb8b89290f991c173ed7cef505aebc79e2e6bf0c29145d84b938d210d7960edfe93810602328cfe31fe8e2147704a78870e3e18aeb72ef6b913e6d4601a367078cd347fb2445f0da81e9181d27af4a42d627e313dc4b3b5923da1bf8143bc3be0cf0680018b289150ba6dc82ffedf1921a7c235526a42abeb2bc51ce16dc1b75ebb843fe0553d348a426beafd205348faf4848ad665faa9a74614ad8fc3a8b5efa7576700cb8205f12e1c7f15a6316470fd2995ff3c68d0bcb80cc63a264d3f32f44b67b0b1b8e9242398222f1ade019c3f9c450083c20af86b2785162011d3fb6b7feca15e0155d53c5d4438fa607baefa8a656db7ebbc0300c30190392fc221023f88e1f0608d2a8e861b9a112ce6200d80ff4027ed5568f5fae8dde8497d79c45421911865e23e9cd52be935ca1de4b7099cab4e7521c8ca90c04b2c141a1557bd379240468594c95444c8c74f47de13b4a246564b5a9f1875b554028ccfd275305490f3bad81bac13ac838b305b3feb13905d3bbd06eb44d46618dfa23a4871ab3b3070913a5884181425cfd2fedabc28eeb3dc379d6490e4cee0332a9ed663b14a315b980ab2ee3abb3e83ce63c4bb7925373e773f13222087abf797a97643d22a42a3a53be1ebe8015775d5f666a9521e90a3a71ef42d83d9ca962c7885a3aea2d")

var Sn_r = common.HexToHash("0x5a8e160331744a86c408f152bc51c3637395faa5dbdd672beecdf85dc3ebcd1b")

var R_r = common.HexToHash("0xc9646ac65155b1326b5f94c2e1bdb19f2f34ecf950561e4a976785cc74450b77")

//refund转账金额
var Cmtr = common.HexToHash("0x89d7665dfb0512bbae245cda0bf423cab0de6f3445070ccc17dee262cc5083e1")

var Refund_proof = []byte("1e5435e471125bc70862bd1d7acb89b1068908049d95fc89aee42767757aa595095aeaf198742b4b747399c0b6fbfe05e0f6db17f58bff969e791bc6153d249d13ad5b51fb48c4223e03665128743047c52834bd12b5adc6143272a054c03d4415eeff3dfcf5509a095542e037022126d76dea061a6940af9da02d62e5d5d6951f31f22cffed65d6e08861a606307cf03a88083969eec5086e9e1ffc93c6acff237c488368ee38f9c9625a10eb38e0b9ff54995519be5e0648b2733d03bccf2c100bb3f8cd2642150fdb39758ec0960fd63e8ffa1d719f8aac6b6017ae1188bf0e631f0cc5657a02afc658797f75b5ad78ad3af4d3a39f9a1e37ea99fed9cca925eb12ac58406d38c0ea3964dbecd639a1abaa7aac72efc4d59466d8e37eeab60d91094a8c2eb431acfd5d8c782bed750ddc3802be92ea2c610327c2dee50af90efe56ca97424d34e3d44237b1123b60a340862cfe6f3554bfea0683aca5db8e2d5526d52cebc3785458bb1e9b9c9a30ae185d314f7486d8a62ccc2659b8f89f2ff91df3cb29e0da3c04084bb4a54faf28b003f1e6a97fc811211341afcda24713bb429b77b7b26e3fb06b2d80f8db48dda948c32033656f9cbf839d92c12cac146c65a844b338865468f210c249d1e6906c3b9b69d0dd97dfc080f756618d7729cfe42171f3fb8e65565368452e520451fb3ca1857bc4c81d63450669b149942b22483ee66b27d88abd7c327951f09b9dd40777ea82ca8ab23b381492d86b34035000e1136452b8518217ef4dbdcddd794eebb953084941b1e439b9be3a1e3d")

var Sn_v_B = common.HexToHash("0x482c99c2421dfbc8517ab8a2d971e365cd32f34eb37f17bd7af342b22790a6f4")

var R_v_B = common.HexToHash("0x3206e16b56b0f6f0d6bcd2ca5999bc93b3f57dd8932bb67ce5c47a4b3862e77c")

//B deposit存入金额
var Cmtv_B = common.HexToHash("0x29e4849093d7c73528c0edac315e84c4119e1e7ba3fa156e3f8f11d23d80fb72")

var Sn_B_new = common.HexToHash("0x7792f54a0b68234ed2a8d3dfaf82ae6fd2b715d5997d0300f7f11b77d8a2c278")

var R_B_new = common.HexToHash("0xc0c7ea0dfd6de3183896bdca10dcd5b1881817f66d24b6ce18330018e4f21793")

//B deposit更新金额
var CmtB_D = common.HexToHash("0x1344f724ace5da092b3c6229a840c5b4e590172159808e6bf54bd6def2e42633")

//B deposit rtcmt
var RT_1 = common.HexToHash("0xad03b0ca053b4579f252b2ac7cf86c3f34a8b91b6b6495c882f0a53419979cd0")

var Deposit_B_proof = []byte("1d748ae30c77d7ec4167132cd2066a5d3aca1a47e00b5ec1392bdb0bf733e24929a6066be14c343148115daccb4c7e96bba3dd1a5af40404c3615ea68d1f9bca094bb4e83c0833a67c19e98b1891d46cdb4a7853350edfe8a053ed2c3e1f2f81280c5fb9f89a808223ffb2db516b3a51f9d9ccc440d796a6cfa2027c3874046b0cb969f23de1c9dde3a883c1c3e8b52e0dcba2a133b2719a51512857b01a0b6f1f78857a75d1a34b3d30d2607874c9e969cc2f5d4689f4f11004e0df69ac6a45188e5501e54a1ab0dfaaa9166b328b72956d1567e4bebac164aa7fc1dedf3d270c09eb95c0392ca9a3e5738c0aad587cf3fecf22bcdf0f802326d0198accb1ca141a890507e0db178ee64a18070f26d6f5af178d9333bb0260c115a680c07dea15e24ba8220c0eb1bea6fe3fb953f6c25dc9edda8065e9e4a906c2ce8f8e3bfb29dca1868d4a05e1c699e4a1aa87caf739f27fb1364c516ed04aa5bea9c90d7c2c5b3c5fdf4ba429bed9421753ebade8ff3a7d6a7307edc9b3579cba8905e65a2be29c909787c906c6bb2bcb8b98468b54efa552023d6e82bb6ba4fdf38aeace14332634c9796129f327cd3b6574bb43155e6a8578babf18624d86784882c5ad1373fd22e7d5909e222e63a0b991a8274f16d1916003436d98a2a268c5f5afe70c5167af5992dda4613f2640ee0767c2b839a08c816e08a1182a07f97fcfc63f0721a4fdf35cd55012054dc9cedc5221aeda6bf815bdb3adb52b659db6eac8582d2b22f85f701e9d0dce25cc63e3fc45bac6d28e27dcc0961c7b7dbb478bd6ad")

var Sn_A_new = common.HexToHash("0x7792f54a0b68234ed2a8d3dfaf82ae6fd2b715d5997d0300f7f11b77d8a2c278")

var Sn_A_v = common.HexToHash("0xef7c718b3694c354bc1a6a03b257e0cfbe3159cb5eec5337d06ecd9dd3ea7e63")

var R_A_new = common.HexToHash("0xc0c7ea0dfd6de3183896bdca10dcd5b1881817f66d24b6ce18330018e4f21793")

var R_A_v = common.HexToHash("0x64e5357c9c90163cd98f45c1c069d8e5b8500307d37a6cff58a12cd86c7ef2f6")

//A deposit更新金额
var CmtA_D = common.HexToHash("0x86d72112136856ed290f5b7fd6e71b4c90a6a964470fb4ccdc2e7a5c0fdd4834")

//A deposit存入金额
var CmtA_v = common.HexToHash("0xf6851b1946b3a2acb99939514eb32d3d2bfbb46614f473b4410fdeb5da2abbc6")

//A deposit rtcmt
var RT_2 = common.HexToHash("0x04a10bf6323b86ae9f16b14cd2d068dea9693698e3d2e1b146848cdaac967c55")

var Deposit_A_proof = []byte("261b93c699d6e4607052dd580d42259655440a142734bc2c064a2d268e9433eb27155e535bd34698eb27e15ca2446e461954f042517dc697139258e1a8a59313050ba1af3ba1bcebc0f8ec130d46bf1f526f8846bd0bebcf2ffa4e03dbad288215c6c48c5819aee61c14e81bc13facbca2461da51a1a2abcf4630153c676d30625cfa9058e4a7e3bd5bd713cc481862ae96baa6cee50d98835b3a2aa138b481005d3e1953969a139634998b659027612ae2debe526e95076a88c983f728e2a5c0e46a5b95d74c162e264962adac0224e51e88bdfb5a432103e8bcf2589719ae30ada8bc79d41e00a2e183f991e7fe624de84ae0b20099e37c919375e130fb9d92cdee5a93483d29bf221338649eee737c5140a70e9cedd84b7f12bc7a67f73d30d6783f49ce8b6eafae53a07aa75d718a257bb56700d39c727476a5e56722cc60ed90485a620dd713005bc4629848cfe71e60212f685b5c5895ed7f4d5dbf9b72536d4c09316393ac740e5a3ad0591991f3c8c1e250bf9d0346c51fb9c4670a1158648a802c39ecfc1094302a8986a1df925d4ff4b36dc77df64d1f000c1ccbc0d57af21495e668b341d90c07c07ab8e0add23b210b8ec9183959b454f2c507a0a651093b0f1bc29256b3bc8381cf2840ac553333b8853f968440d13e07388150138f666c4ae0a31b6df0c8c54da7a2de023dded49ee703552e967bc094f6f562f7e9e59aab9b3bf93a578dfb03a267f5e211f5f72a9d51c7e730cd664234c9b0430744d2eecf1470a2912b4eac6005f137cdd8ac8a92277ff5583e20a89e51b")

var H0 = common.HexToHash("0x41f45b3e32e1e343db9c5d516a1fef38266c0dac56a98c2c304cb2f53cc0079f")

var Hi = common.HexToHash("0x10c43061e59e2522565c4eddc6b8e843304e35670d3dbbcd76b71ed8d3ca0c8f")

func AppendToFile(fileName string, content string) error {
	// 以只写的模式，打开文件
	f, err := os.OpenFile(fileName, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("cacheFileList.yml file create failed. err: " + err.Error())
	} else {
		// 查找文件末尾的偏移量
		n, _ := f.Seek(0, os.SEEK_END)
		// 从末尾的偏移量开始写入内容
		_, err = f.WriteAt([]byte(content), n)
	}
	defer f.Close()
	return err
}
