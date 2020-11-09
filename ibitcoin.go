package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	ut "github.com/yancaitech/go-utils"
)

// bitcoin const
const (
	//COIN                     = 1e8
	//MAX_MONEY                = 21000000 * COIN
	//MAX_BLOCK_WEIGHT         = 4e6
	MessageMagic       = "Bitcoin Signed Message:\n"
	MaxProtocolVersion = 70002
	//LOCKTIME_THRESHOLD       = 500000000
	//MAX_SCRIPT_ELEMENT_SIZE  = 520
	//MAX_BLOCK_SIGOPS_COST    = 80000
	//MAX_PUBKEYS_PER_MULTISIG = 20
	TxSequence = 0x16AEF
	//WITNESS_SCALE_FACTOR     = 4
)

// BitcoinTxIn struct
type BitcoinTxIn struct {
	Txid            string `json:"txid"`
	Vout            uint32 `json:"vout"`
	SignatureScript string `json:"scriptSig"`
	Sequence        uint32 `json:"sequence"`
}

// BitcoinTxOut struct
type BitcoinTxOut struct {
	N       uint32 `json:"n"`
	Value   int64  `json:"value"`
	Address string `json:"address"`
}

// BitcoinTx struct for display
type BitcoinTx struct {
	Txid     string `json:"txid"`
	Version  int32  `json:"version"`
	TxIn     []BitcoinTxIn
	TxOut    []BitcoinTxOut
	LockTime uint32 `json:"locktime"`
	Size     int    `json:"size"`
}

// LoadFromEntropy func
func (k *Key) LoadFromEntropy(entropy string, seed string, m1 uint32, m2 uint32, pubkeycomp bool) (err error) {
	if seed == "hexraw" && len(entropy) == 64 {
		bs, err := hex.DecodeString(entropy)
		if err != nil {
			return err
		}
		err = k.LoadBitcoinHex(bs, pubkeycomp)
		return err
	}
	mnem, err := k.EntropyToMnemonic(entropy)
	if err != nil {
		return err
	}
	err = k.LoadFromMnemonic(mnem, seed, m1, m2, pubkeycomp)
	return err
}

// LoadFromMnemonic func
func (k *Key) LoadFromMnemonic(mnem string, seed string, m1 uint32, m2 uint32, pubkeycomp bool) (err error) {
	// var seedbs []byte
	// if len(seed) == 0 {
	// 	entropy, err := k.EntropyFromMnemonic(mnem)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	seedbs, err = hex.DecodeString(entropy)
	// 	if err != nil {
	// 		return err
	// 	}
	// } else {
	// 	seedbs = bip39.NewSeed(mnem, seed)
	// }
	seedbs := bip39.NewSeed(mnem, seed)
	masterKey, err := bip32.NewMasterKey(seedbs)
	if err != nil {
		return err
	}
	m0, err := masterKey.NewChildKey(m1)
	if err != nil {
		return err
	}
	m00, err := m0.NewChildKey(m2)
	if err != nil {
		return err
	}
	err = k.LoadBitcoinHex(m00.Key, pubkeycomp)
	if err != nil {
		fmt.Println(err)
		return
	}
	return
}

// DumpBitcoinWIF func
func (k *Key) DumpBitcoinWIF(mainnet bool, pubkeycomp bool) (wifkey string, err error) {
	prik, err := PrivateKey(k.PriKey)
	if err != nil {
		return
	}

	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}
	wif, err := btcutil.NewWIF(prik, params, pubkeycomp)
	if err != nil {
		return
	}

	return wif.String(), nil
}

// LoadBitcoinWIF func
func (k *Key) LoadBitcoinWIF(wifkey string) (mainnet bool, pubkeycomp bool, err error) {
	decoded := base58.Decode(wifkey)
	decodedLen := len(decoded)

	// Length of base58 decoded WIF must be 32 bytes + an optional 1 byte
	// (0x01) if compressed, plus 1 byte for netID + 4 bytes of checksum.
	switch decodedLen {
	case 1 + btcec.PrivKeyBytesLen + 1 + 4:
		pubkeycomp = true
	case 1 + btcec.PrivKeyBytesLen + 4:
		pubkeycomp = false
	}

	wif, err := btcutil.DecodeWIF(wifkey)
	if err != nil {
		return
	}
	pri := wif.PrivKey

	k.PriKey, err = privateKeyString(pri)
	if err != nil {
		return
	}

	k.PubKey, err = PublicKeyString(pri.PubKey(), pubkeycomp)
	if err != nil {
		return
	}

	if wif.IsForNet(&chaincfg.MainNetParams) {
		mainnet = true
	} else {
		mainnet = false
	}

	return mainnet, pubkeycomp, nil
}

// LoadBitcoinHex func
func (k *Key) LoadBitcoinHex(hexkey []byte, pubkeycomp bool) (err error) {
	prik, pubk := btcec.PrivKeyFromBytes(btcec.S256(), hexkey)
	k.PriKey, err = privateKeyString(prik)
	if err != nil {
		return err
	}
	k.PubKey, err = PublicKeyString(pubk, pubkeycomp)
	if err != nil {
		return err
	}

	return err
}

// DumpBitcoinHex func
func (k *Key) DumpBitcoinHex() (hexkey []byte, err error) {
	prik, err := PrivateKey(k.PriKey)
	if err != nil {
		return
	}
	hexkey = prik.Serialize()

	return
}

// BitcoinPubKeyString func
func (k *Key) BitcoinPubKeyString(pubkeycomp bool) (pubkey string, err error) {
	pubk, err := publicKey(k.PubKey)
	if err != nil {
		return
	}

	var pubkbs []byte
	if pubkeycomp {
		pubkbs = pubk.SerializeCompressed()
	} else {
		pubkbs = pubk.SerializeUncompressed()
	}
	pubkey = hex.EncodeToString(pubkbs)

	return pubkey, nil
}

// BitcoinAddress func
func (k *Key) BitcoinAddress(mainnet bool, pubkeycomp bool) (addr string, err error) {
	pubk, err := publicKey(k.PubKey)
	if err != nil {
		return
	}

	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}

	var pubkbs []byte
	if pubkeycomp == false {
		pubkbs = pubk.SerializeUncompressed()
	} else {
		pubkbs = pubk.SerializeCompressed()
	}
	pkadr, err := btcutil.NewAddressPubKey(pubkbs, params)
	if err != nil {
		return
	}
	pkh := pkadr.AddressPubKeyHash()
	addr = pkh.EncodeAddress()

	return addr, nil
}

// BitcoinAddressValidate func
func (k *Key) BitcoinAddressValidate(addr string, mainnet bool) (err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}
	_, err = btcutil.DecodeAddress(addr, params)
	return err
}

// BitcoinAddressScript func
func (k *Key) BitcoinAddressScript(mainnet bool, pubkeycomp bool) (script string, err error) {
	pubk, err := publicKey(k.PubKey)
	if err != nil {
		return
	}

	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}

	var pubkbs []byte
	if pubkeycomp == false {
		pubkbs = pubk.SerializeUncompressed()
	} else {
		pubkbs = pubk.SerializeCompressed()
	}
	pkadr, err := btcutil.NewAddressPubKey(pubkbs, params)
	if err != nil {
		return
	}
	hash := pkadr.AddressPubKeyHash()
	bs := hash.Hash160()
	script = "76a914" + hex.EncodeToString(bs[:]) + "88ac"
	// pkh := pkadr.AddressPubKeyHash()
	// addr := pkh.EncodeAddress()
	// hadr, err := btcutil.DecodeAddress(addr, params)
	// if err != nil {
	// 	return
	// }
	// pkScript, err := txscript.PayToAddrScript(hadr)
	// if err != nil {
	// 	return
	// }
	// script = hex.EncodeToString(pkScript)

	return script, nil
}

// WriteVlen Writes varlen field into the given writer
func WriteVlen(b io.Writer, varlen uint64) {
	if varlen < 0xfd {
		b.Write([]byte{byte(varlen)})
		return
	}
	if varlen < 0x10000 {
		b.Write([]byte{0xfd})
		binary.Write(b, binary.LittleEndian, uint16(varlen))
		return
	}
	if varlen < 0x100000000 {
		b.Write([]byte{0xfe})
		binary.Write(b, binary.LittleEndian, uint32(varlen))
		return
	}
	b.Write([]byte{0xff})
	binary.Write(b, binary.LittleEndian, varlen)
}

// BitcoinSignMessage func
func (k *Key) BitcoinSignMessage(msg string, pubkeycomp bool) (sig string, err error) {
	b := new(bytes.Buffer)
	WriteVlen(b, uint64(len(MessageMagic)))
	b.Write([]byte(MessageMagic))
	WriteVlen(b, uint64(len(msg)))
	b.Write([]byte(msg))

	hash := ut.SHA256(b.Bytes())
	hash = ut.SHA256(hash)

	prik, err := PrivateKey(k.PriKey)
	if err != nil {
		return
	}

	//s, err := prik.Sign(hash)
	s, err := btcec.SignCompact(btcec.S256(), prik, hash, pubkeycomp)
	if err != nil {
		return
	}

	sig = base64.StdEncoding.EncodeToString(s)

	return sig, nil
}

// BitcoinVerifyMessage func
func (k *Key) BitcoinVerifyMessage(msg string, sig string, addr string, mainnet bool) (err error) {
	bs, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return
	}

	b := new(bytes.Buffer)
	WriteVlen(b, uint64(len(MessageMagic)))
	b.Write([]byte(MessageMagic))
	WriteVlen(b, uint64(len(msg)))
	b.Write([]byte(msg))

	hash := ut.SHA256(b.Bytes())
	hash = ut.SHA256(hash)

	pubk, c, err := btcec.RecoverCompact(btcec.S256(), bs, hash)
	if err != nil {
		return
	}
	k.PubKey, err = PublicKeyString(pubk, c)
	if err != nil {
		return
	}
	adr1, err := k.BitcoinAddress(mainnet, true)
	adr2, err := k.BitcoinAddress(mainnet, false)
	if adr1 != addr && adr2 != addr {
		return errors.New("verify signature failed")
	}
	s, err := BitcoinRecoverSignature(btcec.S256(), bs, hash)
	if err != nil {
		return err
	}
	if s.Verify(hash, pubk) == false {
		return errors.New("verify signature failed")
	}

	return nil
}

// BitcoinRecoverSignature func
func BitcoinRecoverSignature(curve *btcec.KoblitzCurve, signature []byte, hash []byte) (*btcec.Signature, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, errors.New("invalid compact signature size")
	}

	// format is <header byte><bitlen R><bitlen S>
	sig := &btcec.Signature{
		R: new(big.Int).SetBytes(signature[1 : bitlen+1]),
		S: new(big.Int).SetBytes(signature[bitlen+1:]),
	}

	return sig, nil
}

// BitcoinSignRawTx func
func (k *Key) BitcoinSignRawTx(wifkey string, rawtx string) (signedtx string, err error) {
	var key Key
	mainnet, comp, err := key.LoadBitcoinWIF(wifkey)
	if err != nil {
		return "", err
	}
	script, err := key.BitcoinAddressScript(mainnet, comp)
	if err != nil {
		return "", err
	}
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return "", err
	}
	scriptbs, err := hex.DecodeString(script)
	if err != nil {
		return "", err
	}

	var tx wire.MsgTx
	err = tx.DeserializeNoWitness(bytes.NewReader(bs))
	if err != nil {
		return
	}

	wif, err := btcutil.DecodeWIF(wifkey)
	if err != nil {
		return
	}
	pri := wif.PrivKey

	count := len(tx.TxIn)
	for i := 0; i < count; i++ {
		sig, err := txscript.SignatureScript(&tx, i, scriptbs, txscript.SigHashAll, pri, comp)
		if err != nil {
			return "", err
		}
		tx.TxIn[i].SignatureScript = sig
	}

	var s []byte
	buf := bytes.NewBuffer(s)
	err = tx.SerializeNoWitness(buf)
	if err != nil {
		return "", err
	}
	signedtx = hex.EncodeToString(buf.Bytes())

	return signedtx, nil
}

// BitcoinWifFromEntropy func
func (k *Key) BitcoinWifFromEntropy(entropy string, seed string, m1 uint32, m2 uint32, mainnet bool, pubkeycomp bool) (wif string, err error) {
	var nk Key
	mnem, err := nk.EntropyToMnemonic(entropy)
	if err != nil {
		return "", err
	}
	err = nk.LoadFromMnemonic(mnem, seed, m1, m2, pubkeycomp)
	if err != nil {
		return "", err
	}
	wif, err = nk.DumpBitcoinWIF(mainnet, pubkeycomp)
	if err != nil {
		return "", err
	}
	return wif, nil
}

// BitcoinDecodeRawTxOut func
func (k *Key) BitcoinDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
	totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}

	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	var tx wire.MsgTx
	err = tx.DeserializeNoWitness(bytes.NewReader(bs))
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	if tx.TxOut == nil || len(tx.TxOut) == 0 {
		return 0, 0, 0, "", "", errors.New("no transaction output")
	}

	var i int
	for i = 0; i < len(tx.TxOut); i++ {
		pk, err := txscript.ParsePkScript(tx.TxOut[i].PkScript)
		if err != nil {
			return 0, 0, 0, "", "", err
		}
		adr, err := pk.Address(params)
		if err != nil {
			return 0, 0, 0, "", "", err
		}
		addr := adr.EncodeAddress()
		if addr == fromAddr {
			change = tx.TxOut[i].Value
		} else if addr == toAddr {
			amount = tx.TxOut[i].Value
		}
	}
	if amount <= 0 {
		return 0, 0, 0, "", "", errors.New("bad transaction")
	}
	fee = totalInValue - amount - change
	if fee <= 0 {
		return 0, 0, 0, "", "", errors.New("bad transaction, no fee")
	}

	for i = 0; i < len(tx.TxIn); i++ {
		h := tx.TxIn[i].PreviousOutPoint.Hash
		if len(spendtx) > 0 {
			spendtx += "," + h.String()
		} else {
			spendtx += h.String()
		}
	}

	// dump tx with readable format
	var txs BitcoinTx
	txs.Txid = tx.TxHash().String()
	txs.Version = tx.Version
	txs.LockTime = tx.LockTime
	txs.Size = tx.SerializeSize()
	for i = 0; i < len(tx.TxOut); i++ {
		var txout BitcoinTxOut
		txout.N = uint32(i)
		pk, err := txscript.ParsePkScript(tx.TxOut[i].PkScript)
		if err != nil {
			return 0, 0, 0, "", "", err
		}
		adr, err := pk.Address(params)
		if err != nil {
			return 0, 0, 0, "", "", err
		}
		txout.Address = adr.EncodeAddress()
		txout.Value = tx.TxOut[i].Value
		txs.TxOut = append(txs.TxOut, txout)
	}
	for i = 0; i < len(tx.TxIn); i++ {
		var txin BitcoinTxIn
		txin.Sequence = tx.TxIn[i].Sequence
		txin.SignatureScript = hex.EncodeToString(tx.TxIn[i].SignatureScript)
		txin.Txid = tx.TxIn[i].PreviousOutPoint.Hash.String()
		txin.Vout = tx.TxIn[i].PreviousOutPoint.Index
		txs.TxIn = append(txs.TxIn, txin)
	}

	bs, err = json.MarshalIndent(txs, "", "  ")
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	raw = string(bs)

	return amount, fee, change, raw, spendtx, nil
}

// BitcoinCreateRawTransaction func
func (k *Key) BitcoinCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
	amounts map[string]float64, sequence uint32) (rawtx string, err error) {

	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}

	mtx := wire.NewMsgTx(wire.TxVersion)
	for _, input := range inputs {
		txHash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return "", err
		}
		prevOut := wire.NewOutPoint(txHash, input.Vout)
		txIn := wire.NewTxIn(prevOut, []byte{}, nil)
		if sequence > 0 {
			txIn.Sequence = sequence
		} else {
			txIn.Sequence = TxSequence
		}
		mtx.AddTxIn(txIn)
	}

	for encodedAddr, amount := range amounts {
		if amount <= 0 || amount > btcutil.MaxSatoshi {
			return "", errors.New("Invalid amount")
		}
		addr, err := btcutil.DecodeAddress(encodedAddr, params)
		if err != nil {
			return "", err
		}
		switch addr.(type) {
		case *btcutil.AddressPubKey:
		case *btcutil.AddressPubKeyHash:
		case *btcutil.AddressScriptHash:
		case *btcutil.AddressWitnessPubKeyHash:
		case *btcutil.AddressWitnessScriptHash:
		default:
			return "", errors.New("Invalid address or key")
		}
		if !addr.IsForNet(params) {
			return "", errors.New("Invalid address: " + encodedAddr + " is for the wrong network")
		}
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return "", err
		}
		satoshi, err := btcutil.NewAmount(amount)
		if err != nil {
			return "", err
		}
		txOut := wire.NewTxOut(int64(satoshi), pkScript)
		mtx.AddTxOut(txOut)
	}
	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return "", err
	}
	return mtxHex, nil
}

func messageToHex(msg wire.Message) (string, error) {
	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, MaxProtocolVersion, wire.WitnessEncoding); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf.Bytes()), nil
}

// BitcoinTxid func
func (k *Key) BitcoinTxid(rawtx string) (txid string, err error) {
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return "", err
	}
	var tx wire.MsgTx
	err = tx.DeserializeNoWitness(bytes.NewReader(bs))
	if err != nil {
		return "", err
	}
	txid = tx.TxHash().String()
	return txid, nil
}
