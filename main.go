package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	btccfg "github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	bstxscript "github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bsutil "github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/jessevdk/go-flags"
	mbwire "github.com/martinboehm/btcd/wire"
	"github.com/martinboehm/btcutil"
	"github.com/martinboehm/btcutil/chaincfg"
	"github.com/martinboehm/btcutil/txscript"
	"github.com/minio/blake2b-simd"
	"github.com/tyler-smith/go-bip39"
	"log"
	"net/http"
	"os"
)

var (
	sign      Sign
	broadcast Broadcast
	signAndBroadcast SignAndBroadcast

	MainNetParams chaincfg.Params

	txHeaderBytes          = []byte{0x04, 0x00, 0x00, 0x80}
	txNVersionGroupIDBytes = []byte{0x85, 0x20, 0x2f, 0x89}

	hashPrevOutPersonalization  = []byte("ZcashPrevoutHash")
	hashSequencePersonalization = []byte("ZcashSequencHash")
	hashOutputsPersonalization  = []byte("ZcashOutputsHash")
	sigHashPersonalization      = []byte("ZcashSigHash")
)

const (
	sigHashMask     = 0x1f
	blossomBranchID = 0x2BB40E60

	MainnetMagic mbwire.BitcoinNet = 0x6427e924
)

func init() {
	MainNetParams = chaincfg.MainNetParams
	MainNetParams.Net = MainnetMagic

	// Address encoding magics
	MainNetParams.AddressMagicLen = 2
	MainNetParams.PubKeyHashAddrID = []byte{0x1C, 0xB8} // base58 prefix: t1
	MainNetParams.ScriptHashAddrID = []byte{0x1C, 0xBD} // base58 prefix: t3
}

func main() {
	parser := flags.NewParser(nil, flags.Default)

	_, err := parser.AddCommand("sign",
		"create a multisig signature",
		"Create a signature to release the funds",
		&sign)
	if err != nil {
		log.Fatal(err)
	}
	_, err = parser.AddCommand("broadcast",
		"build and broadcast the transaction",
		"Collect the signatures, build the transaction and broadcast.",
		&broadcast)
	if err != nil {
		log.Fatal(err)
	}

	_, err = parser.AddCommand("signandbroadcast",
		"build and broadcast the transaction",
		"Sign, build the transaction and broadcast.",
		&signAndBroadcast)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := parser.Parse(); err != nil {
		os.Exit(1)
	}
}

type Sign struct {
	Mnemonic string `short:"m" long:"mnemonic" description:"The mnemonic seed for this node"`
}

func (x *Sign) Execute(args []string) error {
	if x.Mnemonic == "" {
		return errors.New("you must enter your mnemonic seed")
	}
	txid, err := chainhash.NewHashFromStr("1af5629f88bd2d72a0a924ae04a16d3964e0ce818e11eb6f5947ccd457b0443b")
	if err != nil {
		return err
	}
	payoutAddress := "t1XkxwDNLYh32y5zLV39VVEojvsxnkgqPa2"
	addr, err := btcutil.DecodeAddress(payoutAddress, params())
	if err != nil {
		return err
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: *wire.NewOutPoint(txid, 0),
			},
		},
		TxOut: []*wire.TxOut{
			{
				PkScript: script,
				Value:    1250902816, // less 5 cent fee
			},
		},
	}

	redeemScript, err := hex.DecodeString("52210323040e80075aaec4fe8047b7a8793c965cb95228cfc78fd4f5ce91fc208f1afe210216433c82383eae2cff28384514a6eabe4b5745b79d35c18bd8a6d7f3373518c72103fafbd0387ce9e7675ab02fd6f65b2858a8c67b4d4a6874ecd96a7c09f1aff71f53ae")
	if err != nil {
		return err
	}

	seed := bip39.NewSeed(x.Mnemonic, "")
	mPrivKey, err := hdkeychain.NewMaster(seed, &btccfg.MainNetParams)
	if err != nil {

		return err
	}

	chaincode, err := hex.DecodeString("c1564f03d569d10a47807b79279b3ba17052a58729f8a85a17838615a23cb24b")
	if err != nil {
		return err
	}
	mECKey, err := mPrivKey.ECPrivKey()
	if err != nil {
		return err
	}

	hdkey, err := childKey(mECKey.Serialize(), chaincode, true)
	if err != nil {
		return err
	}

	priv, err := hdkey.ECPrivKey()
	if err != nil {
		return err
	}

	sig, err := rawTxInSignature(tx, 0, redeemScript, txscript.SigHashAll, priv, 1250990000, 0)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(sig))
	return nil
}

type Broadcast struct {
	BuyerSig  string `long:"buyersig" description:"The buyer's signature'" default:"asdf"`
	VendorSig string `long:"vendorsig" description:"The vendor's signature'"`
}

func (x *Broadcast) Execute(args []string) error {
	if x.BuyerSig == "" {
		return errors.New("buyer sig must be provided")
	}
	if x.VendorSig == "" {
		return errors.New("vendor sig must be provided")
	}

	txid, err := chainhash.NewHashFromStr("1af5629f88bd2d72a0a924ae04a16d3964e0ce818e11eb6f5947ccd457b0443b")
	if err != nil {
		return err
	}
	payoutAddress := "t1XkxwDNLYh32y5zLV39VVEojvsxnkgqPa2"
	addr, err := btcutil.DecodeAddress(payoutAddress, params())
	if err != nil {
		return err
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: *wire.NewOutPoint(txid, 0),
			},
		},
		TxOut: []*wire.TxOut{
			{
				PkScript: script,
				Value:    1250902816, // less 5 cent fee
			},
		},
	}

	redeemScript, err := hex.DecodeString("52210323040e80075aaec4fe8047b7a8793c965cb95228cfc78fd4f5ce91fc208f1afe210216433c82383eae2cff28384514a6eabe4b5745b79d35c18bd8a6d7f3373518c72103fafbd0387ce9e7675ab02fd6f65b2858a8c67b4d4a6874ecd96a7c09f1aff71f53ae")
	if err != nil {
		return err
	}

	buyerSig, err := hex.DecodeString(x.BuyerSig)
	if err != nil {
		return err
	}
	vendorSig, err := hex.DecodeString(x.VendorSig)
	if err != nil {
		return err
	}

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(buyerSig)
	builder.AddData(vendorSig)

	builder.AddData(redeemScript)
	scriptSig, err := builder.Script()
	if err != nil {
		return err
	}
	tx.TxIn[0].SignatureScript = scriptSig

	buf, err := serializeVersion4Transaction(tx, 0)
	if err != nil {
		return err
	}

	resp, err := http.Get(fmt.Sprintf("https://zec.blockbook.api.openbazaar.org/api/sendtx/%s", hex.EncodeToString(buf)))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		fmt.Println("Success!")
	} else {
		fmt.Println("Broadcasting failed")
	}

	return nil
}

type SignAndBroadcast struct {
	Mnemonic string `short:"m" long:"mnemonic" description:"The mnemonic seed for this node"`
}

func (x *SignAndBroadcast) Execute(args []string) error {
	if x.Mnemonic == "" {
		return errors.New("you must enter your mnemonic seed")
	}
	txid, err := chainhash.NewHashFromStr("f88d10f2db8279e0381e54d9e62a894871d9b0f9d29eaa1432ce3b174d2bca84")
	if err != nil {
		return err
	}
	payoutAddress := "35uUXJrQSmnwWZN8FKpyu1JWa4BoywZF65"
	addr, err := bsutil.DecodeAddress(payoutAddress, &btccfg.MainNetParams)
	if err != nil {
		return err
	}
	script, err := bstxscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: *wire.NewOutPoint(txid, 13),
			},
		},
		TxOut: []*wire.TxOut{
			{
				PkScript: script,
				Value:    13085170, // less fee
			},
		},
	}

	redeemScript, err := hex.DecodeString("51210230fadb0ed0268b346a7a832867a8ca9ab354ae99065268876eb56e83f56ed81d2102b306216502593a337123ceac0e420d0be0f400d1c91aad450f205224bdbecd3052ae")
	if err != nil {
		return err
	}

	seed := bip39.NewSeed(x.Mnemonic, "")
	mPrivKey, err := hdkeychain.NewMaster(seed, &btccfg.MainNetParams)
	if err != nil {

		return err
	}

	chaincode, err := hex.DecodeString("dca931eb6117aef0996b3d216fe4d866fc0bd74e7a599b110e30c004159d6255")
	if err != nil {
		return err
	}
	mECKey, err := mPrivKey.ECPrivKey()
	if err != nil {
		return err
	}

	hdkey, err := childKey(mECKey.Serialize(), chaincode, true)
	if err != nil {
		return err
	}

	priv, err := hdkey.ECPrivKey()
	if err != nil {
		return err
	}

	sig, err := bstxscript.RawTxInWitnessSignature(tx, bstxscript.NewTxSigHashes(tx), 0, 13111838, redeemScript, bstxscript.SigHashAll, priv)
	if err != nil {
		return err
	}
	tx.TxIn[0].Witness = append(tx.TxIn[0].Witness, sig)

	var buf bytes.Buffer
	if err := tx.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding); err != nil {
		return err
	}

	fmt.Println("Raw Tx: ", hex.EncodeToString(buf.Bytes()))
	fmt.Println("Txid: ", tx.TxHash().String())

	resp, err := http.Get(fmt.Sprintf("https://btc.blockbook.api.openbazaar.org/api/sendtx/%s", hex.EncodeToString(buf.Bytes())))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		fmt.Println("Broadcast Success!")
	} else {
		fmt.Println("Broadcasting failed")
	}

	return nil
}

func params() *chaincfg.Params {
	if !chaincfg.IsRegistered(&MainNetParams) {
		chaincfg.Register(&MainNetParams)
	}
	return &MainNetParams
}

// rawTxInSignature returns the serialized ECDSA signature for the input idx of
// the given transaction, with hashType appended to it.
func rawTxInSignature(tx *wire.MsgTx, idx int, prevScriptBytes []byte,
	hashType txscript.SigHashType, key *btcec.PrivateKey, amt int64, currentHeight uint64) ([]byte, error) {

	hash, err := calcSignatureHash(prevScriptBytes, hashType, tx, idx, amt, 0, currentHeight)
	if err != nil {
		return nil, err
	}
	signature, err := key.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

func calcSignatureHash(prevScriptBytes []byte, hashType txscript.SigHashType, tx *wire.MsgTx, idx int, amt int64, expiry uint32, currentHeight uint64) ([]byte, error) {

	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.TxIn)-1 {
		return nil, fmt.Errorf("idx %d but %d txins", idx, len(tx.TxIn))
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigHash bytes.Buffer

	// Write header
	_, err := sigHash.Write(txHeaderBytes)
	if err != nil {
		return nil, err
	}

	// Write group ID
	_, err = sigHash.Write(txNVersionGroupIDBytes)
	if err != nil {
		return nil, err
	}

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash chainhash.Hash

	// If anyone can pay isn't active, then we can use the cached
	// hashPrevOuts, otherwise we just write zeroes for the prev outs.
	if hashType&txscript.SigHashAnyOneCanPay == 0 {
		sigHash.Write(calcHashPrevOuts(tx))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// If the sighash isn't anyone can pay, single, or none, the use the
	// cached hash sequences, otherwise write all zeroes for the
	// hashSequence.
	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(calcHashSequence(tx))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// If the current signature mode isn't single, or none, then we can
	// re-use the pre-generated hashoutputs sighash fragment. Otherwise,
	// we'll serialize and add only the target output index to the signature
	// pre-image.
	if hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(calcHashOutputs(tx))
	} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
		var b bytes.Buffer
		wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx])
		sigHash.Write(chainhash.DoubleHashB(b.Bytes()))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// Write hash JoinSplits
	sigHash.Write(make([]byte, 32))

	// Write hash ShieldedSpends
	sigHash.Write(make([]byte, 32))

	// Write hash ShieldedOutputs
	sigHash.Write(make([]byte, 32))

	// Write out the transaction's locktime, and the sig hash
	// type.
	var bLockTime [4]byte
	binary.LittleEndian.PutUint32(bLockTime[:], tx.LockTime)
	sigHash.Write(bLockTime[:])

	// Write expiry
	var bExpiryTime [4]byte
	binary.LittleEndian.PutUint32(bExpiryTime[:], expiry)
	sigHash.Write(bExpiryTime[:])

	// Write valueblance
	sigHash.Write(make([]byte, 8))

	// Write the hash type
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType))
	sigHash.Write(bHashType[:])

	// Next, write the outpoint being spent.
	sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
	var bIndex [4]byte
	binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
	sigHash.Write(bIndex[:])

	// Write the previous script bytes
	wire.WriteVarBytes(&sigHash, 0, prevScriptBytes)

	// Next, add the input amount, and sequence number of the input being
	// signed.
	var bAmount [8]byte
	binary.LittleEndian.PutUint64(bAmount[:], uint64(amt))
	sigHash.Write(bAmount[:])
	var bSequence [4]byte
	binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
	sigHash.Write(bSequence[:])

	branchID := selectBranchID(currentHeight)
	leBranchID := make([]byte, 4)
	binary.LittleEndian.PutUint32(leBranchID, branchID)
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: append(sigHashPersonalization, leBranchID...),
	})
	bl.Write(sigHash.Bytes())
	h := bl.Sum(nil)
	return h[:], nil
}

// serializeVersion4Transaction serializes a wire.MsgTx into the zcash version four
// wire transaction format.
func serializeVersion4Transaction(tx *wire.MsgTx, expiryHeight uint32) ([]byte, error) {
	var buf bytes.Buffer

	// Write header
	_, err := buf.Write(txHeaderBytes)
	if err != nil {
		return nil, err
	}

	// Write group ID
	_, err = buf.Write(txNVersionGroupIDBytes)
	if err != nil {
		return nil, err
	}

	// Write varint input count
	count := uint64(len(tx.TxIn))
	err = wire.WriteVarInt(&buf, wire.ProtocolVersion, count)
	if err != nil {
		return nil, err
	}

	// Write inputs
	for _, ti := range tx.TxIn {
		// Write outpoint hash
		_, err := buf.Write(ti.PreviousOutPoint.Hash[:])
		if err != nil {
			return nil, err
		}
		// Write outpoint index
		index := make([]byte, 4)
		binary.LittleEndian.PutUint32(index, ti.PreviousOutPoint.Index)
		_, err = buf.Write(index)
		if err != nil {
			return nil, err
		}
		// Write sigscript
		err = wire.WriteVarBytes(&buf, wire.ProtocolVersion, ti.SignatureScript)
		if err != nil {
			return nil, err
		}
		// Write sequence
		sequence := make([]byte, 4)
		binary.LittleEndian.PutUint32(sequence, ti.Sequence)
		_, err = buf.Write(sequence)
		if err != nil {
			return nil, err
		}
	}
	// Write varint output count
	count = uint64(len(tx.TxOut))
	err = wire.WriteVarInt(&buf, wire.ProtocolVersion, count)
	if err != nil {
		return nil, err
	}
	// Write outputs
	for _, to := range tx.TxOut {
		// Write value
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, uint64(to.Value))
		_, err = buf.Write(val)
		if err != nil {
			return nil, err
		}
		// Write pkScript
		err = wire.WriteVarBytes(&buf, wire.ProtocolVersion, to.PkScript)
		if err != nil {
			return nil, err
		}
	}
	// Write nLocktime
	nLockTime := make([]byte, 4)
	binary.LittleEndian.PutUint32(nLockTime, tx.LockTime)
	_, err = buf.Write(nLockTime)
	if err != nil {
		return nil, err
	}

	// Write nExpiryHeight
	expiry := make([]byte, 4)
	binary.LittleEndian.PutUint32(expiry, expiryHeight)
	_, err = buf.Write(expiry)
	if err != nil {
		return nil, err
	}

	// Write nil value balance
	_, err = buf.Write(make([]byte, 8))
	if err != nil {
		return nil, err
	}

	// Write nil value vShieldedSpend
	_, err = buf.Write(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	// Write nil value vShieldedOutput
	_, err = buf.Write(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	// Write nil value vJoinSplit
	_, err = buf.Write(make([]byte, 1))
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func calcHashPrevOuts(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		// First write out the 32-byte transaction ID one of whose
		// outputs are being referenced by this input.
		b.Write(in.PreviousOutPoint.Hash[:])

		// Next, we'll encode the index of the referenced output as a
		// little endian integer.
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.PreviousOutPoint.Index)
		b.Write(buf[:])
	}
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: hashPrevOutPersonalization,
	})
	bl.Write(b.Bytes())
	h := bl.Sum(nil)
	return h[:]
}

func calcHashSequence(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.Sequence)
		b.Write(buf[:])
	}
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: hashSequencePersonalization,
	})
	bl.Write(b.Bytes())
	h := bl.Sum(nil)
	return h[:]
}

func calcHashOutputs(tx *wire.MsgTx) []byte {
	var b bytes.Buffer
	for _, out := range tx.TxOut {
		wire.WriteTxOut(&b, 0, 0, out)
	}
	bl, _ := blake2b.New(&blake2b.Config{
		Size:   32,
		Person: hashOutputsPersonalization,
	})
	bl.Write(b.Bytes())
	h := bl.Sum(nil)
	return h[:]
}

func selectBranchID(currentHeight uint64) uint32 {
	return blossomBranchID
}

func childKey(keyBytes []byte, chaincode []byte, isPrivateKey bool) (*hdkeychain.ExtendedKey, error) {
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	var id []byte
	if isPrivateKey {
		id = btccfg.MainNetParams.HDPrivateKeyID[:]
	} else {
		id = btccfg.MainNetParams.HDPublicKeyID[:]
	}
	hdKey := hdkeychain.NewExtendedKey(
		id,
		keyBytes,
		chaincode,
		parentFP,
		0,
		0,
		isPrivateKey)
	return hdKey.Child(0)
}
