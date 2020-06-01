package keys

import (
	"bytes"
	"encoding/hex"
	"errors"

	utils "github.com/yancaitech/go-utils"
	crypto "github.com/yancaitech/go-xrp/crypto"
	"github.com/yancaitech/go-xrp/data"
	xrp "github.com/yancaitech/go-xrp/rpc"
)

// RippleTx struct
type RippleTx struct {
	Txid           string `json:"txid"`
	Sequence       uint32 `json:"sequence"`
	LedgerSequence uint32 `json:"ledgerSequence"`
	Amount         string `json:"amount"`
	Fee            string `json:"fee"`
	FromAddress    string `json:"fromAddr"`
	ToAddress      string `json:"toAddr"`
	Tag            uint32 `json:"tag"`
}

// RippleAddress func
func (k *Key) RippleAddress() (addr string, err error) {
	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", err
	}
	hexstr := hex.EncodeToString(hexkey)
	seed, err := crypto.GenerateFamilySeed(hexstr)
	if err != nil {
		return "", err
	}
	key, err := crypto.NewECDSAKey(seed.Payload())
	if err != nil {
		return "", err
	}
	var zeroSequence uint32
	h, err := crypto.AccountId(key, &zeroSequence)
	if err != nil {
		return "", err
	}
	addr = h.String()

	return addr, nil
}

// RippleAddressValidate func
func (k *Key) RippleAddressValidate(addr string) (err error) {
	_, err = crypto.NewRippleHashCheck(addr, crypto.RIPPLE_ACCOUNT_ID)
	return err
}

// RippleSecret func
func (k *Key) RippleSecret() (secret string, err error) {
	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", err
	}
	hexstr := hex.EncodeToString(hexkey)
	seed, err := crypto.GenerateFamilySeed(hexstr)
	if err != nil {
		return "", err
	}
	secret = seed.String()

	return secret, nil
}

// RippleSignRawTx func
func (k *Key) RippleSignRawTx(entropy string, seed string, m1 uint32, m2 uint32,
	sequence uint32, ledgerSequence uint32,
	toAddr string, tag uint32, value string, currency string, fee string) (txid string, signedtx string, err error) {
	var key Key
	err = key.LoadFromEntropy(entropy, seed, m1, m2, false)
	if err != nil {
		return "", "", err
	}
	fromAddr, err := key.RippleAddress()
	if err != nil {
		return "", "", err
	}
	hexkey, err := key.DumpBitcoinHex()
	if err != nil {
		return "", "", err
	}
	hexstr := hex.EncodeToString(hexkey)
	xrpseed, err := crypto.GenerateFamilySeed(hexstr)
	if err != nil {
		return "", "", err
	}
	xrpkey, err := crypto.NewECDSAKey(xrpseed.Payload())
	if err != nil {
		return "", "", err
	}
	var zeroSequence uint32
	pri := hex.EncodeToString(xrpkey.Private(&zeroSequence))

	client := xrp.NewClient("", "")
	txid, signedtx, err = client.Sign(fromAddr, toAddr, tag, currency,
		value, fee, pri, sequence, ledgerSequence)
	if err != nil {
		return "", "", err
	}

	return txid, signedtx, nil
}

// RippleDecodeRawTxOut func
func (k *Key) RippleDecodeRawTxOut(rawtx string) (txset RippleTx, err error) {
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return txset, err
	}
	r := bytes.NewReader(bs)
	tx, err := data.ReadTransaction(r)
	if err != nil {
		return txset, err
	}
	h, raw, err := data.Raw(tx)
	if err != nil {
		return txset, errors.New("bad transaction")
	}
	if utils.ByteSliceEqual(raw, bs) == false {
		return txset, errors.New("bad transaction")
	}
	pm, ok := (tx).(*data.Payment)
	if ok == false {
		return txset, errors.New("bad transaction")
	}
	txset.Txid = h.String()
	txset.Sequence = pm.Sequence
	txset.LedgerSequence = *pm.LastLedgerSequence
	txset.Amount = pm.Amount.Value.String()
	txset.Fee = pm.Fee.String()
	txset.FromAddress = tx.GetBase().Account.String()
	txset.ToAddress = pm.Destination.String()
	if pm.DestinationTag != nil {
		txset.Tag = *pm.DestinationTag
	} else {
		txset.Tag = 0
	}
	return txset, nil
}

// RippleTxid func
func (k *Key) RippleTxid(rawtx string) (txid string, err error) {
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return "", err
	}
	r := bytes.NewReader(bs)
	tx, err := data.ReadTransaction(r)
	if err != nil {
		return "", err
	}
	h, raw, err := data.Raw(tx)
	if err != nil {
		return "", errors.New("bad transaction")
	}
	if utils.ByteSliceEqual(raw, bs) == false {
		return "", errors.New("bad transaction")
	}
	txid = h.String()
	return txid, err
}
