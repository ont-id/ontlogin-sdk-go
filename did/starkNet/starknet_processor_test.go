package starkNet

import (
	"encoding/hex"
	"fmt"
	"github.com/test-go/testify/assert"
	"testing"
)

func TestStarkNetProcessor_VerifySig(t *testing.T) {
	sp := NewStarkNetProcessor()
	sighex := hex.EncodeToString([]byte("2056925723311714060087095012823799371803452675698110219564697637847120344377,1359148151318872126803000167044754763837524857462869192310619398438650609726"))
	fmt.Printf("sighex:%s\n", sighex)

	sigbts, _ := hex.DecodeString(sighex)

	err := sp.VerifySig("did:starko:063131129C17C35B520B2BB39C176E23876a8E71c4d636B6650E35DD3714b91F", 0, []byte("123456"), sigbts, nil)
	assert.Nil(t, err)
}
