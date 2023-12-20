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
	sp := NewStarkNetProcessor()
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
	text := `{
    "types": {
        "StarkNetDomain": [
            {
                "name": "name",
                "type": "felt"
            },
            {
                "name": "version",
                "type": "felt"
            },
            {
                "name": "chainId",
                "type": "felt"
            }
        ],
        "Server": [
            {
                "name": "name",
                "type": "felt"
            },
            {
                "name": "url",
                "type": "felt"
            },
            {
                "name": "did",
                "type": "felt"
            }
        ],
        "SignData": [
            {
                "name": "type",
                "type": "felt"
            },
            {
                "name": "server",
                "type": "Server"
            },
            {
                "name": "nonce",
                "type": "felt"
            },
            {
                "name": "did",
                "type": "felt"
            },
            {
                "name": "created",
                "type": "felt"
            }
        ]
    },
    "primaryType": "SignData",
    "domain": {
        "name": "TaskOn",
        "version": "1",
        "chainId": "1"
    },
    "message": {
        "type": "ClientResponse",
        "server": {
            "name": "taskon_server",
            "url": "https://taskon.xyz",
            "did": "did:ont:AXdmdzbyf3WZKQzRtrNQwA"
        },
        "nonce": "3416e8f7-9987-11ee-a7df-525400",
        "did": "did:starko:5238e1b23df86c4c0fb",
        "created": 1702451646
    }
}`
	text = `{
    "types": {
        "StarkNetDomain": [
            {
                "name": "name",
                "type": "felt"
            },
            {
                "name": "version",
                "type": "felt"
            },
            {
                "name": "chainId",
                "type": "felt"
            }
        ],
        "Server": [
            {
                "name": "name",
                "type": "felt"
            },
            {
                "name": "url",
                "type": "felt"
            },
            {
                "name": "did",
                "type": "felt"
            }
        ],
        "SignData": [
            {
                "name": "type",
                "type": "felt"
            },
            {
                "name": "server",
                "type": "Server"
            },
            {
                "name": "nonce",
                "type": "felt"
            },
            {
                "name": "did",
                "type": "felt"
            },
            {
                "name": "created",
                "type": "felt"
            }
        ]
    },
    "primaryType": "SignData",
    "domain": {
        "name": "TaskOn",
        "version": "1",
        "chainId": "1"
    },
    "message": {
        "type": "ClientResponse",
        "server": {
            "name": "taskon_server",
            "url": "https://taskon.xyz",
            "did": "did:ont:AXdmdzbyf3WZKQzRtrNQwA"
        },
        "nonce": "063cdd93-9e22-11ee-8266-525400",
        "did": "did:starko:17de689f54abb9f511b",
        "created": 1702957946
    }
}`
	sp := NewStarkNetProcessor()
	sighex := hex.EncodeToString([]byte("2127340877477906885676061420343292598594438784744010720436562455586961918748,794084311332976788600590143198204317118376929615650553802210038039351632157"))
	//fmt.Printf("sighex:%s", sighex)

	sigbts, _ := hex.DecodeString(sighex)

	err := sp.VerifySig("did:starko:0017de689f54abb9f511b0bd5407af91adcac039f4a447c84c29c66b28382a94", 0, []byte(text), sigbts, nil)
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
