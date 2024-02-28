package starknet

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dontpanicdao/caigo/gateway"
	"github.com/dontpanicdao/caigo/types"
	"github.com/test-go/testify/assert"
	"testing"
)

func TestStarkNetProcessor_VerifySig(t *testing.T) {
	sp := NewStarkNetProcessor("")
	sighex := hex.EncodeToString([]byte("2056925723311714060087095012823799371803452675698110219564697637847120344377,1359148151318872126803000167044754763837524857462869192310619398438650609726"))
	fmt.Printf("sighex:%s\n", sighex)

	sigbts, _ := hex.DecodeString(sighex)
	// 0
	did := "did:starko:17de689f54abb9f511b0bd5407af91adcac039f4a447c84c29c66b28382a94"
	msg := []byte(`{"server_name":"taskon","timestamp":1703061573879,"address":"0x17de689f54abb9f511b0bd5407af91adcac039f4a447c84c29c66b28382a94","user_id":520137,"chain_type":"starknet"}`)
	sigbts, _ = hex.DecodeString(`333535393433353337363338313032313435393333363835383736343138393031353034313037383030333533353537353834373731363536323030393731363036313535323339303435302c31363137323234333434383935383632323536393034393238343033343733363033343432353534353232373030303431313932323536383535303131303136343639373437323234393137`)
	err := sp.VerifySig(did, 0, msg, sigbts, nil)
	assert.Nil(t, err)
}

func TestStarkNetProcessor_VerifySig2(t *testing.T) {
	sp := NewStarkNetProcessor("https://starknet-goerli.g.alchemy.com/v2/ZDZ4w7toMJ3dKtu1IrE3To-DePJDb2h9")
	sighex := hex.EncodeToString([]byte("2127340877477906885676061420343292598594438784744010720436562455586961918748,794084311332976788600590143198204317118376929615650553802210038039351632157"))
	//fmt.Printf("sighex:%s", sighex)

	sigbts, _ := hex.DecodeString(sighex)

	did := "did:starko:30fbd441960a53aafcce8659003521ef2a27fb7a56d667572ced3960f305fc4"
	msg := []byte(`{"server_name":"taskon","timestamp":1709108838901,"address":"0x30fbd441960a53aafcce8659003521ef2a27fb7a56d667572ced3960f305fc4","user_id":520137,"chain_type":"starknet"}`)
	sigbts = []byte("1,1006182169185013547284978185661569284231466774613931360233570540299626054360,3565811278148684097366895352819568029580452006562953151514376425859910297173")
	err := sp.VerifySig(did, 0, msg, sigbts, nil)
	assert.Nil(t, err)
}

func TestStarknet(t *testing.T) {
	gw := gateway.NewClient(gateway.WithChain("main"))
	nftAddr := "0x076503062d78f4481be03c9145022d6a4a71ec0719aa07756f79a2384dc7ef16"
	owner := "0x11bab1074b8df82a7148db0251e6cdf67a2017a58ae36b868d66e639a89d066"
	callResp, err := gw.Call(context.Background(), types.FunctionCall{
		ContractAddress:    types.HexToHash(nftAddr),
		EntryPointSelector: "balanceOf",
		Calldata:           []string{owner},
	}, "")
	fmt.Println(err)
	assert.Nil(t, err)
	fmt.Println(callResp)
}
