package keys

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/iqoption/zecutil"
	"golang.org/x/crypto/ripemd160"
)

// IZCash interface
type IZCash interface {
	ZCashAddress(mainnet bool, pubkeycomp bool) (addr string, err error)
	ZCashAddressValidate(addr string, mainnet bool) (err error)

	ZCashCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
		amounts map[string]float64, sequence uint32) (rawtx string, err error)
	ZCashSignRawTx(wifkey string, rawtx string) (signedtx string, err error)
	ZCashDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
		totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error)
	ZCashTxid(rawtx string) (txid string, err error)
}

// ZCashChainParams struct
type ZCashChainParams struct {
	PubHashPrefixes    []byte
	ScriptHashPrefixes []byte
}

var (
	// MainNet param
	MainNet = ZCashChainParams{
		PubHashPrefixes:    []byte{0x1C, 0xB8},
		ScriptHashPrefixes: []byte{0x1C, 0xBD},
	}
	// TestNet3 param
	TestNet3 = ZCashChainParams{
		PubHashPrefixes:    []byte{0x1D, 0x25},
		ScriptHashPrefixes: []byte{0x1C, 0xBA},
	}
	// NetList map
	NetList = map[string]ZCashChainParams{
		"mainnet":  MainNet,
		"testnet3": TestNet3,
		"regtest":  TestNet3,
	}
)

// ZecAddressScriptHash struct
type ZecAddressScriptHash struct {
	hash   [ripemd160.Size]byte
	prefix string
}

// ZecAddressPubKeyHash struct
type ZecAddressPubKeyHash struct {
	hash   [ripemd160.Size]byte
	prefix string
}

// ZecNewAddressPubKeyHash func
func ZecNewAddressPubKeyHash(hash [ripemd160.Size]byte, prefix string) *ZecAddressPubKeyHash {
	return &ZecAddressPubKeyHash{hash, prefix}
}

// ZecNewAddressScriptHash func
func ZecNewAddressScriptHash(hash [ripemd160.Size]byte, prefix string) *ZecAddressScriptHash {
	return &ZecAddressScriptHash{hash, prefix}
}

// ZecEncode pubHash to zec address
func ZecEncode(pkHash []byte, net *chaincfg.Params) (_ string, err error) {
	if _, ok := NetList[net.Name]; !ok {
		return "", errors.New("unknown network parameters")
	}

	var addrPubKey *btcutil.AddressPubKey
	if addrPubKey, err = btcutil.NewAddressPubKey(pkHash, net); err != nil {
		return "", err
	}

	return ZecEncodeHash(btcutil.Hash160(addrPubKey.ScriptAddress())[:ripemd160.Size], NetList[net.Name].PubHashPrefixes)
}

// ZecEncodeHash func
func ZecEncodeHash(addrHash []byte, prefix []byte) (_ string, err error) {
	if len(addrHash) != ripemd160.Size {
		return "", errors.New("incorrect hash length")
	}

	var (
		body  = append(prefix, addrHash[:ripemd160.Size]...)
		chk   = zecAddrChecksum(body)
		cksum [4]byte
	)

	copy(cksum[:], chk[:4])

	return base58.Encode(append(body, cksum[:]...)), nil
}

// ZecDecodeAddress zec address string
func ZecDecodeAddress(address string, netName string) (btcutil.Address, error) {
	var (
		net ZCashChainParams
		ok  bool
	)

	if net, ok = NetList[netName]; !ok {
		return nil, errors.New("unknown net")
	}

	var decoded = base58.Decode(address)
	if len(decoded) != 26 {
		return nil, base58.ErrInvalidFormat
	}

	var cksum [4]byte
	copy(cksum[:], decoded[len(decoded)-4:])

	if zecAddrChecksum(decoded[:len(decoded)-4]) != cksum {
		return nil, base58.ErrChecksum
	}

	if len(decoded)-6 != ripemd160.Size {
		return nil, errors.New("incorrect payload len")
	}

	switch {
	case net.PubHashPrefixes[0] == decoded[0] && net.PubHashPrefixes[1] == decoded[1]:
		addr := &ZecAddressPubKeyHash{prefix: netName}
		copy(addr.hash[:], decoded[2:len(decoded)-4])
		return addr, nil
	case net.ScriptHashPrefixes[0] == decoded[0] && net.ScriptHashPrefixes[1] == decoded[1]:
		addr := &ZecAddressScriptHash{prefix: netName}
		copy(addr.hash[:], decoded[2:len(decoded)-4])
		return addr, nil
	}

	return nil, errors.New("unknown address")
}

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a *ZecAddressPubKeyHash) EncodeAddress() (addr string) {
	addr, _ = ZecEncodeHash(a.hash[:], NetList[a.prefix].PubHashPrefixes)
	return addr
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a pubkey hash.  Part of the Address interface.
func (a *ZecAddressPubKeyHash) ScriptAddress() []byte {
	return a.hash[:]
}

// IsForNet returns whether or not the pay-to-pubkey-hash address is associated
// with the passed bitcoin cash network.
func (a *ZecAddressPubKeyHash) IsForNet(net *chaincfg.Params) bool {
	_, ok := NetList[net.Name]
	if !ok {
		return false
	}
	return a.prefix == net.Name
}

// String returns a human-readable string for the pay-to-pubkey-hash address.
// This is equivalent to calling EncodeAddress, but is provided so the type can
// be used as a fmt.Stringer.
func (a *ZecAddressPubKeyHash) String() string {
	return a.EncodeAddress()
}

// EncodeAddress returns the string encoding of a pay-to-pubkey-hash
// address.  Part of the Address interface.
func (a *ZecAddressScriptHash) EncodeAddress() (addr string) {
	addr, _ = ZecEncodeHash(a.hash[:], NetList[a.prefix].ScriptHashPrefixes)
	return addr
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a pubkey hash.  Part of the Address interface.
func (a *ZecAddressScriptHash) ScriptAddress() []byte {
	return a.hash[:]
}

// IsForNet returns whether or not the pay-to-pubkey-hash address is associated
// with the passed bitcoin cash network.
func (a *ZecAddressScriptHash) IsForNet(net *chaincfg.Params) bool {
	_, ok := NetList[net.Name]
	if !ok {
		return false
	}
	return a.prefix == net.Name
}

// String returns a human-readable string for the pay-to-pubkey-hash address.
// This is equivalent to calling EncodeAddress, but is provided so the type can
// be used as a fmt.Stringer.
func (a *ZecAddressScriptHash) String() string {
	return a.EncodeAddress()
}

func zecAddrChecksum(input []byte) (cksum [4]byte) {
	var (
		h  = sha256.Sum256(input)
		h2 = sha256.Sum256(h[:])
	)
	copy(cksum[:], h2[:4])
	return cksum
}

// ZCashAddress func
func (k *Key) ZCashAddress(mainnet bool, pubkeycomp bool) (addr string, err error) {
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

	addr, err = ZecEncode(pubkbs, params)
	return addr, err
}

// ZCashAddressValidate func
func (k *Key) ZCashAddressValidate(addr string, mainnet bool) (err error) {
	var netdesc = "mainnet"
	if !mainnet {
		netdesc = "testnet3"
	}
	a, err := ZecDecodeAddress(addr, netdesc)
	if err != nil {
		return err
	}
	if !a.IsForNet(&chaincfg.Params{Name: netdesc}) {
		return errors.New("incorrect nettype")
	}
	if a.EncodeAddress() != addr {
		return errors.New("incorrect decode address")
	}
	return nil
}

// ZCashCreateRawTransaction func
func (k *Key) ZCashCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
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
		decoded := base58.Decode(encodedAddr)
		var addr *btcutil.AddressPubKeyHash
		if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], params); err != nil {
			return "", err
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

// ZCashSignRawTx func
func (k *Key) ZCashSignRawTx(wifkey string, rawtx string) (signedtx string, err error) {
	var key Key
	mainnet, comp, err := key.LoadBitcoinWIF(wifkey)
	if err != nil {
		return "", err
	}
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
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

	zecTx := &zecutil.MsgTx{
		MsgTx:        &tx,
		ExpiryHeight: 6000000,
	}

	count := len(tx.TxIn)
	for i := 0; i < count; i++ {
		sig, err := zecutil.SignTxOutput(
			params,
			zecTx,
			i,
			scriptbs,
			txscript.SigHashAll,
			txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
				return pri, comp, nil
			}),
			nil,
			nil,
			0)
		if err != nil {
			return "", err
		}
		tx.TxIn[i].SignatureScript = sig
	}

	var buf bytes.Buffer
	if err = zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err != nil {
		return "", err
	}
	signedtx = hex.EncodeToString(buf.Bytes())

	return signedtx, nil
}
