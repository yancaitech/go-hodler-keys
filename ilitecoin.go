package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ltcsuite/ltcd/btcec"
	"github.com/ltcsuite/ltcd/btcjson"
	"github.com/ltcsuite/ltcd/chaincfg"
	"github.com/ltcsuite/ltcd/chaincfg/chainhash"
	"github.com/ltcsuite/ltcd/txscript"
	"github.com/ltcsuite/ltcd/wire"
	"github.com/ltcsuite/ltcutil"
	"github.com/ltcsuite/ltcutil/base58"
)

const (
	ltcMaxProtocolVersion = 70002
)

// LoadLitecoinWIF func
func (k *Key) LoadLitecoinWIF(wifkey string) (mainnet bool, pubkeycomp bool, err error) {
	decoded := base58.Decode(wifkey)
	decodedLen := len(decoded)
	switch decodedLen {
	case 1 + btcec.PrivKeyBytesLen + 1 + 4:
		pubkeycomp = true
	case 1 + btcec.PrivKeyBytesLen + 4:
		pubkeycomp = false
	}
	wif, err := ltcutil.DecodeWIF(wifkey)
	if err != nil {
		return
	}
	pri := wif.PrivKey
	k.PriKey, err = bytesToBase(pri.Serialize())
	if err != nil {
		return
	}
	var bs []byte
	if pubkeycomp == true {
		bs = pri.PubKey().SerializeCompressed()
	} else {
		bs = pri.PubKey().SerializeUncompressed()
	}
	k.PubKey, err = bytesToBase(bs)
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

// DumpLitecoinWIF func
func (k *Key) DumpLitecoinWIF(ismainnet bool, pubkeycomp bool) (wifkey string, err error) {
	bs, err := baseToBytes(k.PriKey)
	if err != nil {
		return
	}
	prik, _ := btcec.PrivKeyFromBytes(btcec.S256(), bs)
	if prik == nil {
		return "", errors.New("bad private key")
	}
	var params *chaincfg.Params
	if ismainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet4Params
	}
	wif, err := ltcutil.NewWIF(prik, params, pubkeycomp)
	if err != nil {
		return
	}
	return wif.String(), nil
}

// LitecoinAddress func
func (k *Key) LitecoinAddress(mainnet bool, pubkeycomp bool) (addr string, err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet4Params
	}

	wif, err := k.DumpBitcoinWIF(mainnet, pubkeycomp)
	if err != nil {
		return "", err
	}

	w, err := ltcutil.DecodeWIF(wif)
	if err != nil {
		return "", err
	}

	pk := w.SerializePubKey()
	pkHash := ltcutil.Hash160(pk)
	adr, err := ltcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		return "", err
	}
	addr = adr.String()

	return addr, nil
}

// LitecoinAddressValidate func
func (k *Key) LitecoinAddressValidate(addr string, mainnet bool) (err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet4Params
	}
	_, err = ltcutil.DecodeAddress(addr, params)
	return err
}

// LitecoinAddressScript func
func (k *Key) LitecoinAddressScript(mainnet bool, pubkeycomp bool) (script string, err error) {
	wif, err := k.DumpBitcoinWIF(mainnet, pubkeycomp)
	if err != nil {
		return "", err
	}

	w, err := ltcutil.DecodeWIF(wif)
	if err != nil {
		return "", err
	}

	pk := w.SerializePubKey()
	pkHash := ltcutil.Hash160(pk)
	script = "76a914" + hex.EncodeToString(pkHash) + "88ac"

	return script, nil
}

// LitecoinSignRawTx func
func (k *Key) LitecoinSignRawTx(wifkey string, rawtx string) (signedtx string, err error) {
	var key Key
	mainnet, comp, err := key.LoadBitcoinWIF(wifkey)
	if err != nil {
		return "", err
	}
	script, err := key.LitecoinAddressScript(mainnet, comp)
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

	tx := wire.NewMsgTx(1)
	err = tx.BtcDecode(bytes.NewReader(bs), 1, wire.BaseEncoding)
	if err != nil {
		return
	}

	wif, err := ltcutil.DecodeWIF(wifkey)
	if err != nil {
		return
	}
	pri := wif.PrivKey

	count := len(tx.TxIn)
	for i := 0; i < count; i++ {
		sig, err := txscript.SignatureScript(tx, i, scriptbs, txscript.SigHashAll, pri, comp)
		if err != nil {
			return "", err
		}
		tx.TxIn[i].SignatureScript = sig
	}

	var s []byte
	buf := bytes.NewBuffer(s)
	err = tx.Serialize(buf)
	if err != nil {
		return "", err
	}
	signedtx = hex.EncodeToString(buf.Bytes())

	return signedtx, nil
}

// LitecoinDecodeRawTxOut func
func (k *Key) LitecoinDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
	totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet4Params
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

// LitecoinCreateRawTransaction func
func (k *Key) LitecoinCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
	amounts map[string]float64, sequence uint32) (rawtx string, err error) {

	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet4Params
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
		if amount <= 0 || amount > ltcutil.MaxSatoshi {
			return "", errors.New("Invalid amount")
		}
		addr, err := ltcutil.DecodeAddress(encodedAddr, params)
		if err != nil {
			return "", err
		}
		switch addr.(type) {
		case *ltcutil.AddressPubKey:
		case *ltcutil.AddressPubKeyHash:
		case *ltcutil.AddressScriptHash:
		case *ltcutil.AddressWitnessPubKeyHash:
		case *ltcutil.AddressWitnessScriptHash:
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
		satoshi, err := ltcutil.NewAmount(amount)
		if err != nil {
			return "", err
		}
		txOut := wire.NewTxOut(int64(satoshi), pkScript)
		mtx.AddTxOut(txOut)
	}
	mtxHex, err := ltcMessageToHex(mtx)
	if err != nil {
		return "", err
	}
	return mtxHex, nil
}

func ltcMessageToHex(msg wire.Message) (string, error) {
	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, ltcMaxProtocolVersion, wire.WitnessEncoding); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

// LitecoinTxid func
func (k *Key) LitecoinTxid(rawtx string) (txid string, err error) {
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
