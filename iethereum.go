package keys

import (
	"bytes"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"math/big"
	"strings"

	"github.com/yancaitech/go-ethereum/common"
	"github.com/yancaitech/go-ethereum/common/hexutil"
	"github.com/yancaitech/go-ethereum/core/types"
	"github.com/yancaitech/go-ethereum/core/vm"
	"github.com/yancaitech/go-ethereum/crypto"
	"github.com/yancaitech/go-ethereum/params"
	"github.com/yancaitech/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 20
)

// EthereumTx struct
type EthereumTx struct {
	ChainID     *big.Int `json:"chainid"`
	Txid        string   `json:"txid"`
	Nonce       uint64   `json:"nonce"`
	GasLimit    uint64   `json:"gaslimit"`
	GasPrice    *big.Int `json:"gasprice"`
	Recipient   string   `json:"recipient"`
	FromAddress string   `json:"from"`
	Value       *big.Int `json:"value"`
	Payload     string   `json:"payload"`
	V           string   `json:"v"`
	R           string   `json:"r"`
	S           string   `json:"s"`
}

// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// SetBytes sets the address to the value of b.
// If b is larger than len(a) it will panic.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	unchecksummed := hex.EncodeToString(a[:])
	sha := sha3.NewLegacyKeccak256()
	sha.Write([]byte(unchecksummed))
	hash := sha.Sum(nil)

	result := []byte(unchecksummed)
	for i := 0; i < len(result); i++ {
		hashByte := hash[i/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if result[i] > '9' && hashByte > 7 {
			result[i] -= 32
		}
	}
	return "0x" + string(result)
}

// EthereumAddress func
func (k *Key) EthereumAddress() (addr string, err error) {
	pk, err := publicKey(k.PubKey)
	if err != nil {
		return "", err
	}
	bs, err := publicKeyBytes(pk, false)
	if err != nil {
		return "", err
	}
	if len(bs) != 65 {
		return "", errors.New("bad pubkey length")
	}
	hash := Keccak256(bs[1:])[12:]
	adr := BytesToAddress(hash)
	addr = strings.ToLower(adr.Hex())

	return addr, nil
}

// EthereumAddressValidate func
func (k *Key) EthereumAddressValidate(addr string) (err error) {
	rc := common.IsHexAddress(addr)
	if rc == false {
		return errors.New("not ethereum address")
	}
	return nil
}

// EthereumSignMessage func
func (k *Key) EthereumSignMessage(msg string) (sig string, err error) {
	privk, err := k.DumpBitcoinHex()
	if err != nil {
		return "", err
	}
	privs := hex.EncodeToString(privk)

	privateKey, err := crypto.HexToECDSA(privs)
	if err != nil {
		return "", err
	}
	hash := crypto.Keccak256Hash([]byte(msg))

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", err
	}
	sig = hexutil.Encode(signature)

	return sig, nil
}

// EthereumVerifyMessage func
func (k *Key) EthereumVerifyMessage(msg string, sig string, addr string) (err error) {
	hash := crypto.Keccak256Hash([]byte(msg))

	signature, err := hexutil.Decode(sig)
	if err != nil {
		return err
	}

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), signature)
	if err != nil {
		return err
	}

	sigPublicKeyBytes := crypto.FromECDSAPub(sigPublicKeyECDSA)
	if len(sigPublicKeyBytes) != 65 {
		return errors.New("bad pubkey length")
	}

	khash := Keccak256(sigPublicKeyBytes[1:])[12:]
	adr := BytesToAddress(khash).Hex()
	rc := strings.Compare(strings.ToLower(adr), strings.ToLower(addr))
	if rc != 0 {
		return errors.New("verify signature failed")
	}

	return nil
}

// ETHIntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func ETHIntrinsicGas(data []byte, contractCreation, isHomestead bool, isEIP2028 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if contractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * nonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

// EthereumSignRawTx func
func (k *Key) EthereumSignRawTx(entropy string, seed string, m1 uint32, m2 uint32,
	nonce uint64, gasLimit uint64, gasPrice *big.Int, value *big.Int,
	chainID *big.Int, toAddress string) (signedtx string, txid string, err error) {
	var key Key
	err = key.LoadFromEntropy(entropy, seed, m1, m2, false)
	if err != nil {
		return "", "", err
	}
	bs, err := key.DumpBitcoinHex()
	if err != nil {
		return "", "", err
	}
	privkey := hex.EncodeToString(bs)
	privateKey, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return "", "", err
	}
	adrbs := common.HexToAddress(toAddress)
	DataMark := []byte{9, 41, 17}
	tx := types.NewTransaction(nonce, adrbs, value, gasLimit, gasPrice, DataMark)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return "", "", err
	}
	ts := types.Transactions{signedTx}
	rawTxBytes := ts.GetRlp(0)
	signedtx = hex.EncodeToString(rawTxBytes)
	txid = signedTx.Hash().String()

	return signedtx, txid, nil
}

// EthereumSignRawTxERC20 func
func (k *Key) EthereumSignRawTxERC20(entropy string, seed string, m1 uint32, m2 uint32,
	nonce uint64, gasLimit uint64, gasPrice *big.Int, value *big.Int,
	chainID *big.Int, contract string, toAddress string) (signedtx string, txid string, err error) {
	var key Key
	err = key.LoadFromEntropy(entropy, seed, m1, m2, false)
	if err != nil {
		return "", "", err
	}
	bs, err := key.DumpBitcoinHex()
	if err != nil {
		return "", "", err
	}
	privkey := hex.EncodeToString(bs)
	privateKey, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return "", "", err
	}

	contrAddress := common.HexToAddress(contract)
	tokenAddress := common.HexToAddress(toAddress)

	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]

	paddedAddress := common.LeftPadBytes(tokenAddress.Bytes(), 32)
	paddedAmount := common.LeftPadBytes(value.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)

	var zeroV big.Int
	tx := types.NewTransaction(nonce, contrAddress, &zeroV, gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	ts := types.Transactions{signedTx}
	rawTxBytes := ts.GetRlp(0)
	signedtx = hex.EncodeToString(rawTxBytes)
	txid = signedTx.Hash().String()

	return signedtx, txid, nil
}

// EthereumDecodeRawTxOut func
func (k *Key) EthereumDecodeRawTxOut(chainID *big.Int, rawtx string) (txset EthereumTx, err error) {
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return txset, err
	}
	var tx types.Transaction
	err = rlp.Decode(bytes.NewReader(bs), &tx)
	if err != nil {
		return txset, err
	}
	singer := types.NewEIP155Signer(chainID)
	addr, err := singer.Sender(&tx)
	if err != nil {
		return txset, err
	}
	txset.FromAddress = strings.ToLower(addr.String())
	txset.Txid = tx.Hash().String()
	txset.Nonce = tx.Nonce()
	txset.GasLimit = tx.Gas()
	txset.GasPrice = tx.GasPrice()
	txset.Recipient = strings.ToLower(tx.To().String())
	txset.Value = tx.Value()
	txset.Payload = hex.EncodeToString(tx.Data())
	txset.ChainID = chainID
	v, r, s := tx.RawSignatureValues()
	txset.V = hex.EncodeToString(v.Bytes())
	txset.R = hex.EncodeToString(r.Bytes())
	txset.S = hex.EncodeToString(s.Bytes())
	return txset, nil
}

// EthereumTxid func
func (k *Key) EthereumTxid(rawtx string) (txid string, err error) {
	bs, err := hex.DecodeString(rawtx)
	if err != nil {
		return "", err
	}
	var tx types.Transaction
	err = rlp.Decode(bytes.NewReader(bs), &tx)
	if err != nil {
		return "", err
	}
	txid = tx.Hash().String()
	return txid, nil
}
