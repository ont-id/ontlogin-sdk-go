package solana

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58/base58"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"github.com/test-go/testify/assert"
	"testing"
)

func TestSolanaProcessor_VerifySig(t *testing.T) {

	privkeyStr := "2CPZ1UjeaHXqNnJtVRk5NquV7g6zNf8xvN1oKmJCdNikjNR6JdtaTymvC8NZKJ9meXAZb7dbnkcyNMzhHjeiGahm"

	privkey, err := solana.PrivateKeyFromBase58(privkeyStr)
	assert.Nil(t, err)
	pubkey := privkey.PublicKey()
	fmt.Printf("addr:%s\n", pubkey.String())
	//account := solana.NewWallet()
	//fmt.Println("account private key:", account.PrivateKey)
	//fmt.Println("account public key:", account.PublicKey())
	//msg := "hello world"
	//"serverInfo": {
	//	"name": "taskon_server",
	//		"icon": "http://taskon.jpg",
	//		"url": "https://taskon.xyz",
	//		"did": "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
	//		"VerificationMethod": ""
	//}
	//

	msg := &modules.ClientResponseMsg{
		Type: "ClientResponse",
		Server: modules.ServerInfoToSign{
			Name: "taskon_server",
			Url:  "https://taskon.xyz",
			Did:  "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
		},
		Nonce:   "240bca26-84fd-11ed-8d36-f25180c1481a",
		Did:     "did:solo:CFwikhQas7jaSb5kHT5jkvf2sL6iPcE1dz9s2i2n4mD",
		Created: 1672046424,
	}

	msgbts, _ := json.Marshal(msg)

	sig, err := privkey.Sign(msgbts)
	assert.Nil(t, err)
	//bts, err := sig.MarshalText()
	//fmt.Printf("sig bts :%s\n", bts)
	//assert.Nil(t, err)

	sigstr := sig.String()
	fmt.Printf("sig:%s\n", sigstr)
	sigbts, err := base58.Decode(sigstr)
	fmt.Printf("sig hex:%s\n", hex.EncodeToString(sigbts))
	assert.Nil(t, err)

	solprocessor := SolanaProcessor{}

	err = solprocessor.VerifySig(fmt.Sprintf("did:solo:%s", pubkey.String()), 0, msgbts, sigbts)
	assert.Nil(t, err)
}
