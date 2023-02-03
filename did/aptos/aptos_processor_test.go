package aptos

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/test-go/testify/assert"
	"golang.org/x/crypto/ed25519"
	"testing"
)

func TestAptosProcessor_VerifySig(t *testing.T) {

	privkeyhex := "0x95786bd3e2709e853549dbaf020986264baf7e420ea285574cc4b2c292a5a558"
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

	sig := ed25519.Sign(privkey2, []byte(strMsg))

	apProcessor := NewAptosProcessor("https://fullnode.mainnet.aptoslabs.com")
	err = apProcessor.VerifySig("did:apto:ce087617543aaf8130dd40c1fa433eb8716ccc3b4aeb5563b4d1ebfd6f37426d", 0, []byte(strMsg), sig, pubkey)
	assert.Nil(t, err)
}
