package sui

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/fardream/go-bcs/bcs"
	"github.com/ontology-tech/ontlogin-sdk-go/did/sui/sui_types"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
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

func TestSuiProcessor_VerifySig2(t *testing.T) {
	msg := &modules.ClientResponseMsg{
		Type: "ClientResponse",
		Server: modules.ServerInfoToSign{
			Name: "taskon_server",
			Url:  "https://taskon.xyz",
			Did:  "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
		},
		Nonce:   "ce2fe223-f5f5-11ed-995e-525400516d2d",
		Did:     "did:suio:9eaf9bef9fc7e9eab7fcc6d37aab6d78aaaf138e469611bb80abda21e861e008",
		Created: 1684467677,
	}
	msgbts, err := json.Marshal(msg)
	assert.Nil(t, err)

	sig := "0x086ff5b902162c0e412c02bda112b754463a49b7301ce341fdef46eae149f76e92b93087975c7f93e394a2bc412152f529936fc0ef168ae9dddc22c3c95f5f24550eea114dfae099c3a2a159c6da6433da15ba3bb5b581ca728ae215c03ab"
	sigbts, err := hexutil.Decode(sig)
	assert.Nil(t, err)
	sp := NewSuiProcessor()
	err = sp.VerifySig("did:suio:9eaf9bef9fc7e9eab7fcc6d37aab6d78aaaf138e469611bb80abda21e861e008", 0, msgbts, sigbts[1:len(sigbts)-32], sigbts[len(sigbts)-32:])
	assert.Nil(t, err)

}

func TestSuiProcessor_VerifySig3(t *testing.T) {
	msg := &modules.ClientResponseMsg{
		Type: "ClientResponse",
		Server: modules.ServerInfoToSign{
			Name: "taskon_server",
			Url:  "https://taskon.xyz",
			Did:  "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
		},
		Nonce:   "3a5e19ad-2f50-11ee-a07f-52540038ea50",
		Did:     "did:suio:b991c63472b156206c03f5dda19c562c2caf0b741334016e23c07b1d33cfafe0",
		Created: 1690773211,
	}
	msgbts, err := json.Marshal(msg)
	assert.Nil(t, err)

	msgbts = []byte(`{"type":"ClientResponse","server":{"name":"taskon_server","url":"https://taskon.xyz","did":"did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt"},"nonce":"ce05836d-9fc5-11ee-8f53-52540038ea50","did":"did:suio:9f222bfee9374314e3144524a9faa4f4e43a820e497feb3bfe635db6b0ce37b5","created":1703138240}`)
	sig := "AABzJNEd1ZV/3HplB0+3um/V7AKl3Z/SNb0sc3Twjh+UNCPCZxgQ4uNhZWmUGjJM3XTFdG4t5Hs/NWSPgnZhQAqY7stwbTKd+8kN6A6hmZpH2jTnR01YRAxNLluM9pRqvA=="
	sig = "ACdxkVAZckldq2O/XSsOPzUX3uXO5/QTFgmAuhoQNrix4tvEj+6XxIVvAAMQOIiyC0ei+ezVIYiB0a20gVg3GwKY7stwbTKd+8kN6A6hmZpH2jTnR01YRAxNLluM9pRqvA=="
	sigbts, _ := base64.StdEncoding.DecodeString(sig)
	assert.Nil(t, err)
	sp := NewSuiProcessor()
	fmt.Println(hex.EncodeToString(sigbts[len(sigbts)-32:]))

	msgbts, _ = base64.StdEncoding.DecodeString("eyJ0eXBlIjoiQ2xpZW50UmVzcG9uc2UiLCJzZXJ2ZXIiOnsibmFtZSI6InRhc2tvbl9zZXJ2ZXIiLCJ1cmwiOiJodHRwczovL3Rhc2tvbi54eXoiLCJkaWQiOiJkaWQ6b250OkFYZG1kemJ5ZjNXWktRelJ0ck5Rd0FSOTFaeE1VZmhYa3QifSwibm9uY2UiOiI0OTMwMjI3MS05ZmNjLTExZWUtOGY1My01MjU0MDAzOGVhNTAiLCJkaWQiOiJkaWQ6c3Vpbzo5ZjIyMmJmZWU5Mzc0MzE0ZTMxNDQ1MjRhOWZhYTRmNGU0M2E4MjBlNDk3ZmViM2JmZTYzNWRiNmIwY2UzN2I1IiwiY3JlYXRlZCI6MTcwMzE0MTAyNH0=")
	fmt.Println(hex.EncodeToString(msgbts))

	err = sp.VerifySig("did:suio:9f222bfee9374314e3144524a9faa4f4e43a820e497feb3bfe635db6b0ce37b5", 0, msgbts, sigbts[1:len(sigbts)-32], sigbts[len(sigbts)-32:])
	assert.Nil(t, err)

}
