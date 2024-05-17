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

func TestEIP712_2(t *testing.T) {
	processor := EthProcessor{}
	sig := hexutil.MustDecode("0xdb674aab37fd01d57bf4840b64cf3f6e910611c214c3aa6eae3f9f996d020f6b4ec3a8b1bc137652887ec4a571cbfc464022be8310c24fb033e98be18aeae4d91b")
	data := did.EIP712Msg{
		Type:       "ClientResponse",
		ServerName: "orange_server",
		ServerURL:  "https://www.orangeprotocol.io/",
		ServerDid:  "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
		Did:        "did:etho:6a426c1e07ccba3401197eb1e9ec8fc6152da239",
		Nonce:      "607395a6-1421-11ef-8440-52540038ea50",
		Created:    1715931905,
	}

	f := processor.VerifySigEIP712("did:etho:6A426c1e07cCBA3401197Eb1E9EC8Fc6152dA239", 1, nil, sig, nil, data)
	assert.Nil(t, f)
	// hash, err := GetEIP712SignHash()
	// assert.Nil(t, err)
	// f := ETHVerifySig("0x6A426c1e07cCBA3401197Eb1E9EC8Fc6152dA239", sig, hash)
	// assert.True(t, f)

}
