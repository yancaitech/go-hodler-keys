package keys

import (
	"encoding/hex"

	polka "github.com/yancaitech/go-polka"
	dotconfig "github.com/yancaitech/go-polka/config"
)

// PolkadotAddress func
func (k *Key) PolkadotAddress() (addr string, err error) {
	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", err
	}
	addr, err = polka.DotAddress(hexkey, dotconfig.PolkadotPrefix)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// PolkadotAddressValidate func
func (k *Key) PolkadotAddressValidate(addr string) (err error) {
	err = polka.DotAddressValidate(addr, dotconfig.PolkadotPrefix)
	return err
}

// PolkadotCreateSignedTransaction func
func (k *Key) PolkadotCreateSignedTransaction(toAddr string, amount, nonce, fee uint64) (txid, txSigned string, err error) {
	fromAddr, err := k.PolkadotAddress()
	if err != nil {
		return "", "", err
	}
	hexkey, err := k.DumpBitcoinHex()
	if err != nil {
		return "", "", err
	}
	blockHash := "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3"
	// XXX: Era calc has not implement, immortal era now.
	var blockHeight uint64 = 228774800
	hexstr := hex.EncodeToString(hexkey)
	txid, txSigned, err = polka.DotCreateSignedTransaction(fromAddr, toAddr,
		amount, nonce, fee,
		uint32(25), uint32(5), "0500",
		hexstr,
		blockHash, blockHash, blockHeight)
	if err != nil {
		return "", "", err
	}
	return txid, txSigned, nil
}

// PolkadotDecodeSignedTransaction func
func (k *Key) PolkadotDecodeSignedTransaction(txSigned string) (txid, txjson string, err error) {
	txid, txjson, err = polka.DotDecodeSignedTransaction(txSigned)
	if err != nil {
		return "", "", err
	}
	return txid, txjson, nil
}
