package eth

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ontology-tech/ontlogin-sdk-go/did"
	"github.com/test-go/testify/assert"
)

func TestEIP712(t *testing.T) {
	processor := EthProcessor{}
	sig := hexutil.MustDecode("0x39beb1ae2b09029909a949d3677822d6030509b3a9cd6cb60b58653bcb865aa032917d6fc10a965600ea1bf55f71b3249def4b679e3d0cda2e7cd4fed514fac71c")
	data := did.EIP712Msg{
		Type:       "ClientResponse",
		ServerName: "orange_server",
		ServerURL:  "https://www.orangeprotocol.io/",
		ServerDid:  "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
		Did:        "did:etho:6A426c1e07cCBA3401197Eb1E9EC8Fc6152dA239",
		Nonce:      "12313123131124",
		Created:    1715831360336,
	}

	f := processor.VerifySigEIP712("did:etho:6A426c1e07cCBA3401197Eb1E9EC8Fc6152dA239", 1, nil, sig, nil, data)
	assert.Nil(t, f)
	// hash, err := GetEIP712SignHash()
	// assert.Nil(t, err)
	// f := ETHVerifySig("0x6A426c1e07cCBA3401197Eb1E9EC8Fc6152dA239", sig, hash)
	// assert.True(t, f)

}
