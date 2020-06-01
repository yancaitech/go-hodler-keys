package keys

import (
	"context"
	"encoding/hex"
	"encoding/json"

	eos "github.com/yancaitech/go-eos"
	eosecc "github.com/yancaitech/go-eos/ecc"
	"github.com/yancaitech/go-eos/token"
)

// EOSPublicKey func
func (k *Key) EOSPublicKey() (pubkey string, err error) {
	wif, err := k.DumpBitcoinWIF(true, true)
	if err != nil {
		return "", err
	}

	prik, err := eosecc.NewPrivateKey(wif)
	if err != nil {
		return "", err
	}

	pubk := prik.PublicKey()
	pubkey = pubk.String()

	return pubkey, nil
}

// EOSSignRawTx func
func (k *Key) EOSSignRawTx(entropy string, seed string, m1 uint32, m2 uint32,
	chainID string, headBlockID string,
	fromAccount string, toAccount string, quantity string, memo string) (signedtx string, err error) {
	api := eos.New("")

	txOpts := &eos.TxOptions{}
	txOpts.ChainID, err = hex.DecodeString(chainID)
	txOpts.HeadBlockID, err = hex.DecodeString(headBlockID)

	var key Key
	err = key.LoadFromEntropy(entropy, seed, m1, m2, true)
	if err != nil {
		return "", err
	}
	pk, err := key.DumpBitcoinWIF(true, true)
	if err != nil {
		return "", err
	}

	keyBag := &eos.KeyBag{}
	err = keyBag.ImportPrivateKey(context.Background(), pk)
	if err != nil {
		return "", err
	}
	api.SetSigner(keyBag)

	from := eos.AccountName(fromAccount)
	to := eos.AccountName(toAccount)
	asset, err := eos.NewEOSAssetFromString(quantity)
	if err != nil {
		return "", err
	}

	tx := eos.NewTransaction([]*eos.Action{token.NewTransfer(from, to, asset, memo)}, txOpts)
	_, packedTx, err := api.SignTransaction(context.Background(), tx, txOpts.ChainID, eos.CompressionNone)
	if err != nil {
		return "", err
	}

	content, err := json.MarshalIndent(packedTx, "", "  ")
	if err != nil {
		return "", err
	}
	signedtx = string(content)

	return signedtx, nil
}
