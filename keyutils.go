package keys

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"io/ioutil"

	"github.com/btcsuite/btcd/btcec"
	base "github.com/multiformats/go-multibase"
)

func bytesZip(bs []byte) (z []byte, err error) {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		return
	}
	_, err = w.Write(bs)
	w.Close()
	if err != nil {
		return
	}
	z = b.Bytes()
	return z, nil
}

func bytesUnzip(z []byte) (bs []byte, err error) {
	r := flate.NewReader(bytes.NewBuffer(z))
	defer r.Close()
	bs, err = ioutil.ReadAll(r)
	if err != nil && err != io.ErrUnexpectedEOF {
		return
	}
	return bs, nil
}

func bytesToBase(bs []byte) (s string, err error) {
	s, err = base.Encode(base.Base58BTC, bs)
	return s, err
}

func baseToBytes(s string) (bs []byte, err error) {
	_, bs, err = base.Decode(s)
	if err != nil {
		return
	}
	return bs, nil
}

// PrivateKey func
func PrivateKey(s string) (pk *btcec.PrivateKey, err error) {
	bs, err := baseToBytes(s)
	if err != nil {
		return
	}
	pk, _ = btcec.PrivKeyFromBytes(btcec.S256(), bs)
	if pk == nil {
		return nil, errors.New("bad private key")
	}
	return pk, nil
}

func privateKeyString(pk *btcec.PrivateKey) (s string, err error) {
	s, err = bytesToBase(pk.Serialize())
	if err != nil {
		return
	}
	return s, nil
}

func publicKey(s string) (pk *btcec.PublicKey, err error) {
	bs, err := baseToBytes(s)
	if err != nil {
		return
	}
	pk, err = btcec.ParsePubKey(bs, btcec.S256())
	if err != nil {
		return
	}
	return pk, nil
}

// PublicKeyString func
func PublicKeyString(pk *btcec.PublicKey, pubkeycomp bool) (s string, err error) {
	var bs []byte
	if pubkeycomp == true {
		bs = pk.SerializeCompressed()
	} else {
		bs = pk.SerializeUncompressed()
	}
	s, err = bytesToBase(bs)
	if err != nil {
		return
	}
	return s, nil
}

func publicKeyBytes(pk *btcec.PublicKey, pubkeycomp bool) (bs []byte, err error) {
	if pubkeycomp == true {
		bs = pk.SerializeCompressed()
	} else {
		bs = pk.SerializeUncompressed()
	}
	return bs, nil
}
