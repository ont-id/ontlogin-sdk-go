package tron

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/test-go/testify/assert"
	"testing"
)

type T struct {
	Foo string `json:"foo"`
}

func TestTronProcessor_VerifySig(t *testing.T) {
	did := "did:trono:TXHXGAyTnZnQQH5TdGpu6Q2Bg8oVo6VZTU"

	//temp := T{Foo: "bar"}
	//
	//msg := hexutil.Encode([]byte("helloworld"))
	sig := "0xb8ea080d26b92075c29b1a1b09f20f8625232b1db9fc65a258f16a5f7f41b4f02ac19dced74a7c7923c31a07b5aa31600da130c3c8aef0d23cf674d905fac2841b"
	sigbts, _ := hexutil.Decode(sig)

	p := NewTronProcessor()
	err := p.VerifySig(did, 0, []byte("helloworld"), sigbts, nil)
	assert.Nil(t, err, "err not nil")
}
