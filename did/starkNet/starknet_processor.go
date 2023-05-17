package starkNet

import (
	"context"
	"fmt"
	"github.com/dontpanicdao/caigo"
	"github.com/dontpanicdao/caigo/gateway"
	"github.com/dontpanicdao/caigo/types"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"math/big"
	"strings"
)

type StarkNetProcessor struct{}

func NewStarkNetProcessor() *StarkNetProcessor {
	return &StarkNetProcessor{}
}

func (s StarkNetProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {

	address, err := getStarkAddrFromDID(did)
	if err != nil {
		return err
	}
	hash, err := caigo.Curve.PedersenHash([]*big.Int{types.StrToBig(string(msg))})
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("address:%s\n", address)
	fmt.Printf("hash:%s\n", hash)

	sigArr := strings.Split(string(sig), ",")
	fmt.Printf("%v\n", sigArr)
	fmt.Printf("calldata:%v\n", append([]string{fmt.Sprintf("%d", hash), fmt.Sprintf("%d", len(sigArr))}, sigArr...))

	gw := gateway.NewClient(gateway.WithChain("main"))

	callResp, err := gw.Call(context.Background(), types.FunctionCall{
		ContractAddress:    types.HexToHash(address),
		EntryPointSelector: "isValidSignature",
		Calldata:           append([]string{fmt.Sprintf("%d", hash), fmt.Sprintf("%d", len(sigArr))}, sigArr...),
	}, "")
	if err != nil {
		return err
	}
	if len(callResp) != 1 {
		return fmt.Errorf("verify sig failed")
	}
	if callResp[0] != "0x1" {
		return fmt.Errorf("verify sig failed")
	}
	return nil
}

func (s StarkNetProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s StarkNetProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	//TODO implement me
	panic("implement me")
}

func (s StarkNetProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	//TODO implement me
	panic("implement me")
}

func (s StarkNetProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func getStarkAddrFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "starko" {
		return "", fmt.Errorf(modules.ERR_NOT_SOL_DID)
	}
	return "0x" + arr[2], nil
}
