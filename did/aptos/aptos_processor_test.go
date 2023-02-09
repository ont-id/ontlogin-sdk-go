package aptos

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/test-go/testify/assert"
	"golang.org/x/crypto/ed25519"
	"testing"
)

func TestAptosProcessor_VerifySig(t *testing.T) {

	privkeyhex := "<yourkey>"
	privkeybts, err := hexutil.Decode(privkeyhex)
	assert.Nil(t, err)

	//privkey := ed25519.PrivateKey(privkeybts)
	//
	//pubkey := privkey.Public().(ed25519.PublicKey)
	//addr := SingleSignerAuthKey(pubkey)
	//fmt.Println(hexutil.Encode(addr[:]))

	privkey2 := ed25519.NewKeyFromSeed(privkeybts)
	pubkey := privkey2.Public().(ed25519.PublicKey)
	addr := SingleSignerAuthKey(pubkey)
	fmt.Println(hexutil.Encode(addr[:]))

	strMsg := "hello world"

	msgWithPrefix := append([]byte("APTOS\nmessage: "), []byte(strMsg)...)
	//msgWithPrefix := []byte("APTOS\nmessage: " + strMsg)

	sig := ed25519.Sign(privkey2, msgWithPrefix)
	fmt.Printf("====sig1:%s\n", hexutil.Encode(sig))

	msg2 := "APTOS\nmessage: " + strMsg
	fmt.Printf("====sig2:%s\n", hexutil.Encode(ed25519.Sign(privkey2, []byte(msg2))))

	sig2, _ := hexutil.Decode("0x6031ee8182e7cb742e3cbedea3b8389c9cb4934dda7f54dd324a6e4ed01a9fbdebe2d52f4d09bde8d660f6982c9f733d5dd37be392b763a1cfed8baaf1011e0b")

	apProcessor := NewAptosProcessor("https://fullnode.mainnet.aptoslabs.com")
	err = apProcessor.VerifySig("did:apto:207fc13512c322ea6c9e1c8fe9ecbd4b6761c6d66e09f5fd6e880c45e059bc26", 0, msgWithPrefix, sig, pubkey)
	assert.Nil(t, err)

	err = apProcessor.VerifySig("did:apto:207fc13512c322ea6c9e1c8fe9ecbd4b6761c6d66e09f5fd6e880c45e059bc26", 0, msgWithPrefix, sig2, pubkey)
	assert.Nil(t, err)
}

func TestPubkey(t *testing.T) {
	pubkey := "<youkey>"
	pubkeybts, _ := hexutil.Decode(pubkey)
	addr := SingleSignerAuthKey(pubkeybts)
	fmt.Printf("addr:%s\n", hexutil.Encode(addr[:]))
}

func TestSig(t *testing.T) {
	privkeyhex := "<your key>"
	privkeybts, err := hexutil.Decode(privkeyhex)
	assert.Nil(t, err)

	//privkey := ed25519.PrivateKey(privkeybts)
	//
	//pubkey := privkey.Public().(ed25519.PublicKey)
	//addr := SingleSignerAuthKey(pubkey)
	//fmt.Println(hexutil.Encode(addr[:]))

	privkey2 := ed25519.NewKeyFromSeed(privkeybts)
	pubkey := privkey2.Public().(ed25519.PublicKey)
	addr := SingleSignerAuthKey(pubkey)
	fmt.Println(hexutil.Encode(addr[:]))

	strMsg := "{\"type\":\"ClientResponse\",\"server\":{\"name\":\"taskon_server\",\"url\":\"https://taskon.xyz\",\"did\":\"did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt\"},\"nonce\":\"98c927fe-a829-11ed-92a9-525400516d2d\",\"did\":\"did:apto:d0c8061e50b6e8ace6cd47d10b6037e3b9593310cf8b66c3a975c81738f119a5\",\"created\":1675913212}"
	sig := ed25519.Sign(privkey2, []byte(strMsg))

	fmt.Printf("sig:%s\n", hexutil.Encode(sig))
}
