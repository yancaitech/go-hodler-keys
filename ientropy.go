package keys

import (
	"encoding/hex"

	"github.com/tyler-smith/go-bip39"
)

// GenerateEntropy func
func (k *Key) GenerateEntropy(bitsize int) (entropy string, err error) {
	bs, err := bip39.NewEntropy(bitsize)
	if err != nil {
		return "", err
	}
	entropy = hex.EncodeToString(bs)
	return entropy, nil
}

// EntropyToMnemonic func
func (k *Key) EntropyToMnemonic(entropy string) (mnem string, err error) {
	bs, err := hex.DecodeString(entropy)
	if err != nil {
		return
	}
	mnem, err = bip39.NewMnemonic(bs)
	if err != nil {
		return
	}
	return mnem, nil
}

// EntropyFromMnemonic func
func (k *Key) EntropyFromMnemonic(mnem string) (entropy string, err error) {
	bs, err := bip39.EntropyFromMnemonic(mnem)
	if err != nil {
		return "", err
	}
	entropy = hex.EncodeToString(bs)
	return entropy, nil
}

// GenerateMnemonic func
func (k *Key) GenerateMnemonic(bitsize int) (mnem string, err error) {
	entropy, err := bip39.NewEntropy(bitsize)
	if err != nil {
		return
	}
	mnem, err = bip39.NewMnemonic(entropy)
	if err != nil {
		return
	}
	return
}
