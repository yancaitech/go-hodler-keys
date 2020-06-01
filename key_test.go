package keys

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestXrpTx(t *testing.T) {
	k := Key{}
	raw := "12000024003E65D92E00003039201B034C04576140000000000F4240684000000000001022732103A671F98137D264E89D763A03C6E40540968925E7221A1572E4353672C211BECC74463044022023FA8F437F4CB336BCC1C28A6AF224A645AA7EA15988FE11FA050A62A1585FC6022043C9DA62274D4DCE71BD27A1DF53D011FB67D9BB4070F5F9FAF4C0DD610849218114874F36A544D4C968EA258E52B50D5ED283C29C1083145BD0D77F8396276B0482A5383DC72CC6240CB0E3"
	tx, err := k.RippleDecodeRawTxOut(raw)
	fmt.Println(tx, err)

	txid, err := k.RippleTxid(raw)
	fmt.Println(txid, err)
}

func TestETHAddress(t *testing.T) {
	// Private key: 0958cecb9d7cd417fe2c24b51b03210b0ffa2713ae4e777f0609a34204767b25
	// Address: 0x2e92b9F394fB20a8c0B3376EDe6B9a7F244C70D7
	k := Key{}
	bs, err := hex.DecodeString("0958cecb9d7cd417fe2c24b51b03210b0ffa2713ae4e777f0609a34204767b25")
	k.LoadBitcoinHex(bs, true)
	addr, err := k.EthereumAddress()
	fmt.Println(addr, err)
}

func TestEOSPubkey(t *testing.T) {
	// Description	EOS Token Sale Claim Key
	// Public key	EOS8HRBxDhAQ4n1LFN2Ycsk9TLavTbXDHrVydcVZm2bNkcpUwWADo
	// Private key	5Ke21RGXFCntRoH42KrX8asUVAprBtuE7oVcb4zXr8NdB19KRNY
	k := Key{}
	k.LoadBitcoinWIF("5Ke21RGXFCntRoH42KrX8asUVAprBtuE7oVcb4zXr8NdB19KRNY")
	pk, err := k.EOSPublicKey()
	fmt.Println(pk, err)
}

func TestBitcoinDecodeRawTx(t *testing.T) {
	k := Key{}

	amount, fee, change, raw, spendtx, err := k.BitcoinDecodeRawTxOut(true, "1LXFYigyLVY1SKRVLTEUaAEDSawU2LGZxN", "13gFuqio5jeYQ2daUgX4x8guxoQmFyCnUP",
		2009176,
		"0100000003ca2673b14c99747e83dd0f5b62aa24bebf3c7b32661b9705f24c9ecc496339220000000000ffffffff994f2d0771eb81f3bb67917ab1c3f906876b592e99c6845c21b8df8c3fec57d20000000000ffffffff25027e869536db7e1ed3f7fa4588746767cbbafd54299db379adf246676d9dee0000000000ffffffff0157a81e00000000001976a9141d5cebd299654d1d23ae3392bb67e079c974116888ac00000000")

	fmt.Println(amount, fee, change, raw, spendtx, err)
}

func TestLTCKey(t *testing.T) {
	k := Key{}
	hexk, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142")
	k.LoadBitcoinHex(hexk, false)

	btcaddr, err := k.BitcoinAddress(true, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(btcaddr, err)

	bchaddr, err := k.LitecoinAddress(true, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(bchaddr, err)
}

func TestBCHKey(t *testing.T) {
	k := Key{}
	k.Generate()

	btcaddr, err := k.BitcoinAddress(true, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(btcaddr, err)

	bchaddr, err := k.BitcoinCashAddress(true, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(bchaddr, err)
}

func TestBCHSign(t *testing.T) {
	k := Key{}
	k.Generate()

	k.BitcoinSVAddress(true, true)

	k.BitcoinSVDecodeRawTxOut(true, "1JgasYbPWEpQr7LWd3bDhJ7AwYeKFWt6tf",
		"19EXwtZT8emnTeopozh7Y2YQEkLCJ8fbsB",
		10750000, "0100000001edfaa8534f4d0f73c49265cfaf52f025e5d72cc40649fb8ec25d17ed27d1fd860000000000ef6a010002a0860100000000001976a9145a503f1a4ba64871b103b2d692bedee18bd5fac788aca87da200000000001976a914c1f6a2a35de06be7574cec073ead39f5cb56096588ac00000000")

	w, _ := k.DumpBitcoinWIF(true, true)
	s, _ := k.BitcoinSVSignRawTx(w, "0100000001b8bf89629117eb6335ac50ba183d9b2cdc1f4f36e48e12bff9f0c8f8ce9e4efc0000000000ef6a0100013008a400000000001976a914c1f6a2a35de06be7574cec073ead39f5cb56096588ac00000000:[10760000]")
	fmt.Println(s)
}

func TestETHSignMsg(t *testing.T) {
	k := Key{}
	k.Generate()

	sig, err := k.EthereumSignMessage("hello")
	if err != nil {
		t.Fatal(err)
	}

	adr, err := k.EthereumAddress()
	if err != nil {
		t.Fatal(err)
	}

	err = k.EthereumVerifyMessage("hello", sig, adr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestKeyGenerator(t *testing.T) {
	k := Key{}
	err := k.Generate()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Private Key:", k.PriKey)
	fmt.Println("Public  Key:", k.PubKey)
}

func TestKeySign(t *testing.T) {
	k := Key{}
	err := k.Generate()
	if err != nil {
		t.Fatal(err)
	}
	s, err := k.Sign("1")
	if err != nil {
		t.Fatal(err)
	}
	//fmt.Println("Signature len:", len(s))
	fmt.Println("Signature  :", s)
	err = k.Verify("1", s)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Sign/Verify OK")
}

func TestKeyCrypto(t *testing.T) {
	//text := `{"method":"UserService.CreateUser","params":[{"Name":"Merak","Pass":"PASS"}],"id":5577006791947779410}`
	text := "123"
	k := Key{}
	err := k.Generate()
	if err != nil {
		t.Fatal(err)
	}
	en, err := k.Encrypt(text)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Encrypt len:", len(en))
	fmt.Println("Encrypt    :", en)
	data, err := k.Decrypt(en)
	if err != nil {
		t.Fatal(err)
	}
	if data != text {
		t.Fatal()
	}
	fmt.Println("Encrypt/Decrypt OK")
}
