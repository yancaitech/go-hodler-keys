package keys

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

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
