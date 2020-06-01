package keys

import (
	"math/big"

	"github.com/btcsuite/btcd/btcjson"
)

// Key pair
type Key struct {
	PriKey string
	PubKey string
}

// IKey base interface
type IKey interface {
	// Generate key pair
	Generate() (err error)

	// Sign the data
	Sign(data string) (sign string, err error)

	// Verify the data and sign
	Verify(data string, sign string) (err error)

	// Encrypt func
	Encrypt(data string) (en string, err error)

	// Decrypt func
	Decrypt(en string) (data string, err error)
}

// IEntropy interface
type IEntropy interface {
	GenerateEntropy(bitsize int) (entropy string, err error)
	GenerateMnemonic(bitsize int) (mnem string, err error)

	EntropyToMnemonic(entropy string) (mnem string, err error)
	EntropyFromMnemonic(mnem string) (entropy string, err error)
}

// IBitcoin interface
type IBitcoin interface {
	LoadFromEntropy(entropy string, seed string, m1 uint32, m2 uint32, pubkeycomp bool) (err error)
	LoadFromMnemonic(mnem string, seed string, m1 uint32, m2 uint32, pubkeycomp bool) (err error)

	// WIF format private key
	LoadBitcoinWIF(wifkey string) (mainnet bool, pubkeycomp bool, err error)
	DumpBitcoinWIF(ismainnet bool, pubkeycomp bool) (wifkey string, err error)

	// hex format private key
	LoadBitcoinHex(hexkey []byte, pubkeycomp bool) (err error)
	DumpBitcoinHex() (hexkey []byte, err error)

	BitcoinPubKeyString(pubkeycomp bool) (pubkey string, err error)
	BitcoinAddress(mainnet bool, pubkeycomp bool) (addr string, err error)
	BitcoinAddressValidate(addr string, mainnet bool) (err error)

	BitcoinSignMessage(msg string, pubkeycomp bool) (sig string, err error)
	BitcoinVerifyMessage(msg string, sig string, addr string, mainnet bool) (err error)

	// utils
	BitcoinWifFromEntropy(entropy string, seed string,
		m1 uint32, m2 uint32, mainnet bool, pubkeycomp bool) (wif string, err error)
	BitcoinCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
		amounts map[string]float64, sequence uint32) (rawtx string, err error)
	BitcoinSignRawTx(wifkey string, rawtx string) (signedtx string, err error)
	BitcoinDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
		totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error)
	BitcoinTxid(rawtx string) (txid string, err error)
}

// IBitcoinCash interface
type IBitcoinCash interface {
	BitcoinCashAddress(mainnet bool, pubkeycomp bool) (addr string, err error)
	BitcoinCashAddressValidate(addr string, mainnet bool) (err error)

	BitcoinCashCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
		amounts map[string]float64, sequence uint32) (rawtx string, err error)
	BitcoinCashSignRawTx(wifkey string, rawtx string) (signedtx string, err error)
	BitcoinCashDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
		totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error)
	BitcoinCashTxid(rawtx string) (txid string, err error)
}

// IBitcoinSV interface
type IBitcoinSV interface {
	BitcoinSVAddress(mainnet bool, pubkeycomp bool) (addr string, err error)
	BitcoinSVAddressValidate(addr string, mainnet bool) (err error)

	BitcoinSVCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
		amounts map[string]float64, sequence uint32) (rawtx string, err error)
	BitcoinSVSignRawTx(wifkey string, rawtx string) (signedtx string, err error)
	BitcoinSVDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
		totalInValue int64, rawtx string) (amount int64, fee int64, change int64, raw string, spendtx string, err error)
	BitcoinSVTxid(rawtx string) (txid string, err error)
}

// ILitecoin interface
type ILitecoin interface {
	// WIF format private key
	LoadLitecoinWIF(wifkey string) (mainnet bool, pubkeycomp bool, err error)
	DumpLitecoinWIF(ismainnet bool, pubkeycomp bool) (wifkey string, err error)

	LitecoinAddress(mainnet bool, pubkeycomp bool) (addr string, err error)
	LitecoinAddressValidate(addr string, mainnet bool) (err error)

	LitecoinCreateRawTransaction(mainnet bool, inputs []btcjson.TransactionInput,
		amounts map[string]float64, sequence uint32) (rawtx string, err error)
	LitecoinSignRawTx(wifkey string, rawtx string) (signedtx string, err error)
	LitecoinDecodeRawTxOut(mainnet bool, fromAddr string, toAddr string,
		totalInValue int64, rawtx string) (amount int64, fee int64, change int64, spendtx string, raw string, err error)
	LitecoinTxid(rawtx string) (txid string, err error)
}

// IEthereum interface
type IEthereum interface {
	EthereumAddress() (addr string, err error)
	EthereumAddressValidate(addr string) (err error)

	EthereumSignMessage(msg string) (sig string, err error)
	EthereumVerifyMessage(msg string, sig string, addr string) (err error)

	EthereumSignRawTx(entropy string, seed string, m1 uint32, m2 uint32,
		nonce uint64, gasLimit uint64, gasPrice *big.Int, value *big.Int,
		chainID *big.Int, toAddress string) (signedtx string, txid string, err error)
	EthereumSignRawTxERC20(entropy string, seed string, m1 uint32, m2 uint32,
		nonce uint64, gasLimit uint64, gasPrice *big.Int, value *big.Int,
		chainID *big.Int, contract string, toAddress string) (signedtx string, txid string, err error)
	EthereumDecodeRawTxOut(rawtx string) (chainID *big.Int, txset EthereumTx, err error)
	EthereumTxid(rawtx string) (txid string, err error)
}

// IRipple interface
type IRipple interface {
	RippleAddress() (addr string, err error)
	RippleAddressValidate(addr string) (err error)
	RippleSecret() (secret string, err error)

	RippleSignRawTx(entropy string, seed string, m1 uint32, m2 uint32,
		sequence uint32, ledgerSequence uint32,
		toAddr string, tag uint32, value string, currency string, fee string) (txid string, signedtx string, err error)
	RippleDecodeRawTxOut(rawtx string) (txset RippleTx, err error)
	RippleTxid(rawtx string) (txid string, err error)
}
