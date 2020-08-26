package keys

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	filutils "github.com/yancaitech/go-filutils"
)

// FilecoinAddress func
func (k *Key) FilecoinAddress() (addr string, err error) {
	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", err
	}
	hexstr := hex.EncodeToString(hexkey)
	pk, err := filutils.LoadFromPrivateKey(hexstr)
	if err != nil {
		return "", err
	}
	return pk.Address.String(), nil
}

// FilecoinAddressValidate func
func (k *Key) FilecoinAddressValidate(addr string) (err error) {
	var adr filutils.Address
	err = adr.Scan(addr)
	return err
}

// FilecoinKeyInfo func
func (k *Key) FilecoinKeyInfo() (info string, err error) {
	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", err
	}
	hexstr := hex.EncodeToString(hexkey)
	pk, err := filutils.LoadFromPrivateKey(hexstr)
	if err != nil {
		return "", err
	}
	info, err = pk.DumpKeyInfo()
	if err != nil {
		return "", err
	}
	return info, nil
}

// FilecoinLoadKeyInfo func
func (k *Key) FilecoinLoadKeyInfo(info string) (err error) {
	key, err := filutils.LoadKeyInfo(info)
	if err != nil {
		return err
	}

	sk, err := key.DumpPrivateKey()
	if err != nil {
		return err
	}

	bs, err := hex.DecodeString(sk)
	if err != nil {
		return err
	}

	err = k.LoadBitcoinHex(bs, false)
	return err
}

// FilecoinDecodeRawTx func
func (k *Key) FilecoinDecodeRawTx(rawtx string) (signedtx string, err error) {
	stx, err := filutils.DecodeSignedTransaction(rawtx)
	if err != nil {
		return "", err
	}

	bs, err := json.MarshalIndent(stx, "", "  ")
	if err != nil {
		return "", err
	}
	signedtx = string(bs)

	return signedtx, nil
}

// FilecoinSignRawTx func
func (k *Key) FilecoinSignRawTx(entropy string, seed string, m1 uint32, m2 uint32,
	nonce uint64, fromAccount string, toAccount string,
	val uint64, gp uint64, gl uint64,
	method uint64, params []byte) (signedtx string, hextx string, txid string, err error) {

	var key Key
	err = key.LoadFromEntropy(entropy, seed, m1, m2, false)
	if err != nil {
		return "", "", "", err
	}
	fromAddr, err := key.FilecoinAddress()
	if err != nil {
		return "", "", "", err
	}
	if fromAccount != fromAddr {
		return "", "", "", errors.New("address not match key")
	}

	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", "", "", err
	}
	hexstr := hex.EncodeToString(hexkey)
	pk, err := filutils.LoadFromPrivateKey(hexstr)
	if err != nil {
		return "", "", "", err
	}
	sk, err := pk.DumpPrivateKey()
	if err != nil {
		return "", "", "", err
	}

	raw, err := filutils.CreateTransaction(fromAccount,
		toAccount,
		filutils.NewIntUnsigned(val),
		int64(gl),
		filutils.NewIntUnsigned(gp),
		nonce,
		method,
		params)
	if err != nil {
		return "", "", "", err
	}

	tx, err := filutils.DecodeTransaction(raw)
	if err != nil {
		return "", "", "", err
	}

	stx, err := filutils.SignMessage(sk, tx)
	if err != nil {
		return "", "", "", err
	}

	bs, err := json.MarshalIndent(stx, "", "  ")
	if err != nil {
		return "", "", "", err
	}
	signedtx = string(bs)

	bs, err = stx.Serialize()
	if err != nil {
		return "", "", "", err
	}
	hextx = hex.EncodeToString(bs)

	txid = stx.Cid().String()

	return signedtx, hextx, txid, nil
}
