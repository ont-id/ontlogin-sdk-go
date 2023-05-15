package sui

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/fardream/go-bcs/bcs"
	"github.com/ontology-tech/ontlogin-sdk-go/did/sui/sui_types"
	"github.com/test-go/testify/assert"
	"golang.org/x/crypto/blake2b"
	"testing"
)

func TestDecodeSignature(t *testing.T) {
	s := "AOgHExsGmUQAnv2XF00X4UByuHgnJJKLRoA6jTnIGXkfHGQeEkFXbhcsBghO4w2qrmBC9E2OPAPxNSW21IG/nglFUO6hAU364JnDoqFZxtpkM9oVuju1tYHKcoriFcA6Cw=="
	bts, err := base64.StdEncoding.DecodeString(s)
	assert.Nil(t, err)
	fmt.Printf("%v\n", bts)
	fmt.Printf("len:%d\n", len(bts))
	fmt.Printf("%v\n", bts[len(bts)-32:])

	pubkey := ed25519.PublicKey(bts[len(bts)-32:])
	fmt.Printf("%s\n", hexutil.Encode(pubkey))
	tmp := []byte{0}
	tmp = append(tmp, pubkey...)
	addrBytes := blake2b.Sum256(tmp)
	address := "0x" + hex.EncodeToString(addrBytes[:])[:ADDRESS_LENGTH]
	fmt.Printf("address:%s\n", address)

	text := "123456"
	encodedBytes := []byte(text)

	value := sui_types.NewIntentMessage(sui_types.Intent{
		Scope: sui_types.IntentScope{
			PersonalMessage: &sui_types.EmptyEnum{},
		},
		Version: sui_types.IntentVersion{
			V0: &sui_types.EmptyEnum{},
		},
		AppId: sui_types.AppId{
			Sui: &sui_types.EmptyEnum{},
		},
	}, sui_types.Base64Data(encodedBytes))
	fmt.Printf("value:%v\n", value)
	message, err := bcs.Marshal(value)
	assert.Nil(t, err)
	fmt.Printf("message:%v\n", message)

	hash := blake2b.Sum256(message)

	sigbts := bts[1 : len(bts)-32]
	fmt.Printf("sigbts:%v\n", sigbts)

	//msgWithPrefix := append([]byte("SUI\nmessage: "), msg...)
	//msgWithPrefix := append([]byte("message"), msg...)
	//msgWithPrefix = append(msgWithPrefix, []byte("\nnonce: 1")...)

	f := ed25519.Verify(pubkey, hash[:], sigbts)
	assert.True(t, f)

	//flag := bts[0:1]
	//fmt.Printf("%s\n", bts[:])

}

func TestSuiProcessor_VerifySig(t *testing.T) {
	s := "AOgHExsGmUQAnv2XF00X4UByuHgnJJKLRoA6jTnIGXkfHGQeEkFXbhcsBghO4w2qrmBC9E2OPAPxNSW21IG/nglFUO6hAU364JnDoqFZxtpkM9oVuju1tYHKcoriFcA6Cw=="
	bts, _ := base64.StdEncoding.DecodeString(s)

	sp := NewSuiProcessor()
	err := sp.VerifySig("did:suio:9eaf9bef9fc7e9eab7fcc6d37aab6d78aaaf138e469611bb80abda21e861e008", 0, []byte("123456"), bts[1:len(bts)-32], bts[len(bts)-32:])
	assert.Nil(t, err, "error")
}
