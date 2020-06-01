package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gcash/bchd/btcjson"
	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/txscript"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/yancaitech/go-utils"
)

const (
	bchMaxProtocolVersion = wire.NoValidationRelayVersion
)

// BitcoinCashAddress func
func (k *Key) BitcoinCashAddress(mainnet bool, pubkeycomp bool) (addr string, err error) {
	btcaddr, err := k.BitcoinAddress(mainnet, pubkeycomp)

	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}

	address, err := bchutil.DecodeAddress(btcaddr, params)
	if err != nil {
		return "", err
	}
	address2, err := bchutil.NewAddressPubKeyHash(address.ScriptAddress(), params)
	if err != nil {
		return "", err
	}
	addr = address2.String()

	return addr, nil
}

// BitcoinCashAddressValidate func
func (k *Key) BitcoinCashAddressValidate(addr string, mainnet bool) (err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}
	_, err = bchutil.DecodeAddress(addr, params)
	return err
}

// BitcoinCashSignRawTx func
func (k *Key) BitcoinCashSignRawTx(wifkey string, rawtx string) (signedtx string, err error) {
	sl := strings.Split(rawtx, ":")
	if len(sl) != 2 {
		return "", errors.New("rawtx format incorrect, raw:[a1,a2,...]")
	}
	rawtx = sl[0]
	var amounts []int64
	err = json.Unmarshal([]byte(sl[1]), &amounts)
	if err != nil {
		return "", errors.New("rawtx format incorrect, raw:[a1,a2,...]")
	}
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

	tx := wire.NewMsgTx(1)
	err = tx.BchDecode(bytes.NewReader(bs), 1, wire.BaseEncoding)
	if err != nil {
		return "", err
	}

	wif, err := bchutil.DecodeWIF(wifkey)
	if err != nil {
		return "", err
	}
	pri := wif.PrivKey

	count := len(tx.TxIn)
	if count != len(amounts) {
		return "", errors.New("txin count != amounts")
	}
	for i := 0; i < count; i++ {
		sig, err := txscript.SignatureScript(tx, i, amounts[i], scriptbs, txscript.SigHashAll, pri, comp)
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
	signedtx += ":"
	signedtx += sl[1]

	return signedtx, nil
}

// BitcoinCashDecodeRawTxOut func
func (k *Key) BitcoinCashDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
	totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error) {
	var params *chaincfg.Params
	if mainnet {
		params = &chaincfg.MainNetParams
	} else {
		params = &chaincfg.TestNet3Params
	}

	froma, err := bchutil.DecodeAddress(fromAddr, params)
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	fromhash := froma.ScriptAddress()
	toa, err := bchutil.DecodeAddress(toAddr, params)
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	tohash := toa.ScriptAddress()

	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	tx := wire.NewMsgTx(1)
	err = tx.BchDecode(bytes.NewReader(bs), 1, wire.BaseEncoding)
	if err != nil {
		return 0, 0, 0, "", "", err
	}
	if tx.TxOut == nil || len(tx.TxOut) == 0 {
		return 0, 0, 0, "", "", errors.New("no transaction output")
	}

	var i int
	for i = 0; i < len(tx.TxOut); i++ {
		_, adr, _, err := txscript.ExtractPkScriptAddrs(tx.TxOut[i].PkScript, params)
		if err != nil {
			return 0, 0, 0, "", "", err
		}
		addr := adr[0].ScriptAddress()
		if utils.ByteSliceEqual(addr, fromhash) {
			change = tx.TxOut[i].Value
		} else if utils.ByteSliceEqual(addr, tohash) {
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
		pk, err := txscript.ParsePkScript(tx.TxOut[i].PkScript, params)
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

// BitcoinCashCreateRawTransaction func
func (k *Key) BitcoinCashCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
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
		txIn := wire.NewTxIn(prevOut, []byte{})
		if sequence > 0 {
			txIn.Sequence = sequence
		} else {
			txIn.Sequence = TxSequence
		}
		mtx.AddTxIn(txIn)
	}
	for encodedAddr, amount := range amounts {
		if amount <= 0 || amount > bchutil.MaxSatoshi {
			return "", errors.New("Invalid amount")
		}
		addr, err := bchutil.DecodeAddress(encodedAddr, params)
		if err != nil {
			return "", err
		}
		switch addr.(type) {
		case *bchutil.AddressPubKeyHash:
		case *bchutil.AddressScriptHash:
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
		satoshi, err := bchutil.NewAmount(amount)
		if err != nil {
			return "", err
		}
		txOut := wire.NewTxOut(int64(satoshi), pkScript)
		mtx.AddTxOut(txOut)
	}
	mtxHex, err := bchMessageToHex(mtx)
	if err != nil {
		return "", err
	}
	return mtxHex, nil
}

func bchMessageToHex(msg wire.Message) (string, error) {
	var buf bytes.Buffer
	if err := msg.BchEncode(&buf, bchMaxProtocolVersion, wire.BaseEncoding); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

// BitcoinCashTxid func
func (k *Key) BitcoinCashTxid(rawtx string) (txid string, err error) {
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return "", err
	}
	tx := wire.NewMsgTx(1)
	err = tx.BchDecode(bytes.NewReader(bs), 1, wire.BaseEncoding)
	if err != nil {
		return "", err
	}
	txid = tx.TxHash().String()
	return txid, nil
}
