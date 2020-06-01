package keys

import (
	"errors"

	"github.com/btcsuite/btcd/btcec"
	mh "github.com/multiformats/go-multihash"
)

// Generate the key pair
func (k *Key) Generate() (err error) {
	pri, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return
	}

	k.PriKey, err = privateKeyString(pri)
	if err != nil {
		return
	}

	// default pubkey format: compressed
	k.PubKey, err = PublicKeyString(pri.PubKey(), true)
	if err != nil {
		return
	}

	return nil
}

// Sign the data
func (k *Key) Sign(data string) (sign string, err error) {
	prik, err := PrivateKey(k.PriKey)
	if err != nil {
		return
	}

	hash, err := mh.Encode([]byte(data), mh.SHA2_256)
	if err != nil {
		return
	}

	s, err := prik.Sign(hash)
	if err != nil {
		return
	}

	sign, err = bytesToBase(s.Serialize())
	if err != nil {
		return
	}

	return sign, nil
}

// Verify the data and signature
func (k *Key) Verify(data string, sign string) (err error) {
	pk, err := publicKey(k.PubKey)
	if err != nil {
		return
	}

	hash, err := mh.Encode([]byte(data), mh.SHA2_256)
	if err != nil {
		return
	}

	bs, err := baseToBytes(sign)
	if err != nil {
		return
	}

	s, err := btcec.ParseSignature(bs, btcec.S256())
	if err != nil {
		return
	}

	v := s.Verify(hash, pk)
	if v == false {
		return errors.New("Verify signature failed")
	}

	return nil
}

// Encrypt func
func (k *Key) Encrypt(data string) (en string, err error) {
	if len(data) <= 0 {
		return "", nil
	}

	pk, err := publicKey(k.PubKey)
	if err != nil {
		return
	}

	z, err := bytesZip([]byte(data))
	if err != nil {
		return
	}

	bs, err := btcec.Encrypt(pk, z)
	if err != nil {
		return
	}

	en, err = bytesToBase(bs)
	if err != nil {
		return
	}

	return en, nil
}

// Decrypt func
func (k *Key) Decrypt(en string) (data string, err error) {
	if len(en) <= 0 {
		return "", nil
	}

	pk, err := PrivateKey(k.PriKey)
	if err != nil {
		return
	}

	bs, err := baseToBytes(en)
	if err != nil {
		return
	}

	bs, err = btcec.Decrypt(pk, bs)
	if err != nil {
		return
	}

	bs, err = bytesUnzip(bs)
	if err != nil {
		return
	}

	return string(bs), nil
}
