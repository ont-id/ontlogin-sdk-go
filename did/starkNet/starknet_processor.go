package starkNet

import (
	"context"
	"encoding/json"
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

type Types struct {
	StarkNetDomain []DefinitionSpec `json:"StarkNetDomain"`
	Server         []DefinitionSpec `json:"Server"`
	SignData       []DefinitionSpec `json:"SignData"`
}

func parseDefs(params []DefinitionSpec) []caigo.Definition {
	res := make([]caigo.Definition, 0)
	for _, item := range params {
		res = append(res, caigo.Definition{
			Name: item.Name,
			Type: item.Type,
		})
	}
	return res
}

type DefinitionSpec struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type StarkJsonData struct {
	Types       Types            `json:"types"`
	PrimaryType string           `json:"primaryType"`
	Domain      caigo.Domain     `json:"domain"`
	Message     StarkJsonMessage `json:"message"`
}

func (self *StarkJsonData) GetTypeDef() map[string]caigo.TypeDef {
	return map[string]caigo.TypeDef{
		"StarkNetDomain": {
			Definitions: parseDefs(self.Types.StarkNetDomain),
		},
		"Server": {
			Definitions: parseDefs(self.Types.Server),
		},
		"SignData": {
			Definitions: parseDefs(self.Types.SignData),
		},
	}
}

type StarkJsonMessage struct {
	Type   string `json:"type"`
	Server struct {
		Name string `json:"name"`
		Url  string `json:"url"`
		Did  string `json:"did"`
	} `json:"server"`
	Nonce   string `json:"nonce"`
	Did     string `json:"did"`
	Created int    `json:"created"`
}

func (self StarkJsonMessage) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	switch field {
	case "type":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Type).Big())
	case "server":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Server.Name).Big())
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Server.Url).Big())
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Server.Did).Big())
	case "nonce":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Nonce).Big())
	case "did":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Did).Big())
	case "created":
		fmtEnc = append(fmtEnc, types.BigToFelt(big.NewInt(int64(self.Created))).Big())
	}
	return
}

func (s StarkNetProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	address, err := getStarkAddrFromDID(did)
	if err != nil {
		return err
	}
	var sjd StarkJsonData
	if err = json.Unmarshal(msg, &sjd); err != nil {
		return err
	}
	sjd.Message.Did = sjd.Message.Did[:30]
	sjd.Message.Nonce = sjd.Message.Nonce[:30]
	td, err := caigo.NewTypedData(sjd.GetTypeDef(), sjd.PrimaryType, sjd.Domain)
	if err != nil {
		return err
	}
	hash, err := td.GetMessageHash(types.HexToBN(address), sjd.Message, caigo.Curve)
	if err != nil {
		return err
	}
	sigArr := strings.Split(string(sig), ",")
	gw := gateway.NewClient(gateway.WithChain("main"))

	//x := types.HexToBN(address)
	//y := caigo.Curve.GetYCoordinate(x)
	//ok := caigo.Curve.Verify(hash, types.StrToBig(sigArr[0]), types.StrToBig(sigArr[1]), x, y)
	//if ok {
	//	return nil
	//} else {
	//	return fmt.Errorf("verify sig failed")
	//}
	callResp, err := gw.Call(context.Background(), types.FunctionCall{
		ContractAddress:    types.HexToHash(address),
		EntryPointSelector: "isValidSignature",
		Calldata:           append([]string{fmt.Sprintf("%d", hash), fmt.Sprintf("%d", len(sigArr))}, sigArr...),
	}, "")
	if err != nil {
		fmt.Println(err.Error())
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

func (s StarkNetProcessor) VerifySig3(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {

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
		return "", fmt.Errorf(modules.ERR_NOT_STARK_DID)
	}
	return "0x" + arr[2], nil
}
