package starknet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NethermindEth/juno/core/felt"
	"github.com/NethermindEth/starknet.go/rpc"
	"github.com/NethermindEth/starknet.go/utils"
	"github.com/dontpanicdao/caigo"
	"github.com/dontpanicdao/caigo/gateway"
	"github.com/dontpanicdao/caigo/types"
	ethrpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"math/big"
	"strings"
)

type StarkNetProcessor struct {
	rpc string
}

func NewStarkNetProcessor(rpc string) *StarkNetProcessor {
	return &StarkNetProcessor{
		rpc: rpc,
	}
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
	Types       map[string]caigo.TypeDef `json:"types"`
	PrimaryType string                   `json:"primaryType"`
	Domain      caigo.Domain             `json:"domain"`
}

var DefStarkJsonData = StarkJsonData{
	Types: map[string]caigo.TypeDef{
		"StarkNetDomain": caigo.TypeDef{
			Definitions: []caigo.Definition{
				{
					Name: "name",
					Type: "felt",
				},
				{
					Name: "version",
					Type: "felt",
				},
				{
					Name: "chainId",
					Type: "felt",
				},
			},
		},
		"Server": {
			Definitions: []caigo.Definition{
				{
					Name: "name",
					Type: "felt",
				},
				{
					Name: "url",
					Type: "felt",
				},
				{
					Name: "did",
					Type: "felt",
				},
			},
		},
		"SignData": {
			Definitions: []caigo.Definition{
				{
					Name: "type",
					Type: "felt",
				},
				{
					Name: "server",
					Type: "Server",
				},
				{
					Name: "nonce",
					Type: "felt",
				},
				{
					Name: "did",
					Type: "felt",
				},
				{
					Name: "created",
					Type: "felt",
				},
			},
		},
	},
	PrimaryType: "SignData",
	Domain: caigo.Domain{
		Name:    "TaskOn",
		Version: "1",
		ChainId: "1",
	},
}

var DefStarkJsonDataBindAddress = StarkJsonData{
	Types: map[string]caigo.TypeDef{
		"StarkNetDomain": caigo.TypeDef{
			Definitions: []caigo.Definition{
				{
					Name: "name",
					Type: "felt",
				},
				{
					Name: "version",
					Type: "felt",
				},
				{
					Name: "chainId",
					Type: "felt",
				},
			},
		},
		"SignData": {
			Definitions: []caigo.Definition{
				{
					Name: "server_name",
					Type: "felt",
				},
				{
					Name: "timestamp",
					Type: "felt",
				},
				{
					Name: "address",
					Type: "felt",
				},
				{
					Name: "user_id",
					Type: "felt",
				},
				{
					Name: "chain_type",
					Type: "felt",
				},
			},
		},
	},
	PrimaryType: "SignData",
	Domain: caigo.Domain{
		Name:    "TaskOn",
		Version: "1",
		ChainId: "1",
	},
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

func (self *StarkJsonMessage) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
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

type StarkJsonMessageBindAddr struct {
	ServerName string `json:"server_name"` // taskon
	Timestamp  int64  `json:"timestamp"`   // timestamp in second
	Address    string `json:"address"`
	UserId     int64  `json:"user_id"`
	ChainType  string `json:"chain_type"` // evm or solana
}

func (self *StarkJsonMessageBindAddr) FmtDefinitionEncoding(field string) (fmtEnc []*big.Int) {
	switch field {
	case "server_name":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.ServerName).Big())
	case "timestamp":
		fmtEnc = append(fmtEnc, types.BigToFelt(big.NewInt(self.Timestamp)).Big())
	case "address":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.Address).Big())
	case "user_id":
		fmtEnc = append(fmtEnc, types.BigToFelt(big.NewInt(self.UserId)).Big())
	case "chain_type":
		fmtEnc = append(fmtEnc, types.StrToFelt(self.ChainType).Big())
	}
	return
}

func (s StarkNetProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	address, err := getStarkAddrFromDID(did)
	if err != nil {
		return err
	}
	var hash *big.Int
	if strings.Contains(string(msg), "chain_type") {
		var msgRaw StarkJsonMessageBindAddr
		if err = json.Unmarshal(msg, &msgRaw); err != nil {
			return err
		}
		td, err := caigo.NewTypedData(DefStarkJsonDataBindAddress.Types, DefStarkJsonDataBindAddress.PrimaryType,
			DefStarkJsonDataBindAddress.Domain)
		if err != nil {
			return err
		}
		hash, err = td.GetMessageHash(types.HexToBN(address), &msgRaw, caigo.Curve)
		if err != nil {
			return err
		}
	} else {
		var msgRaw StarkJsonMessage
		if err = json.Unmarshal(msg, &msgRaw); err != nil {
			return err
		}
		msgRaw.Did = truncate(msgRaw.Did, 30)
		msgRaw.Server.Did = truncate(msgRaw.Server.Did, 30)
		msgRaw.Nonce = truncate(msgRaw.Nonce, 30)
		td, err := caigo.NewTypedData(DefStarkJsonData.Types, DefStarkJsonData.PrimaryType, DefStarkJsonData.Domain)
		if err != nil {
			return err
		}
		hash, err = td.GetMessageHash(types.HexToBN(address), &msgRaw, caigo.Curve)
		if err != nil {
			return err
		}
	}
	sigArr := strings.Split(string(sig), ",")
	//https://starknet-mainnet.g.alchemy.com/v2/usp9JoVk_YNLJFnU5WiyfoWAMLK3KRg_
	c, err := ethrpc.DialContext(context.Background(), s.rpc)
	if err != nil {
		return err
	}
	clientv02 := rpc.NewProvider(c)
	contractAddr, err := utils.HexToFelt(address)
	if err != nil {
		return err
	}
	sigArrFelt, err := utils.HexArrToFelt(sigArr)
	if err != nil {
		return err
	}
	err = verifySigOld(clientv02, contractAddr, hash, len(sigArr), sigArrFelt)
	if err == nil {
		return nil
	}
	err = verifySigNew(clientv02, contractAddr, hash, len(sigArr), sigArrFelt)
	if err == nil {
		return nil
	}
	return err
}

func verifySigOld(clientv02 *rpc.Provider, contractAddr *felt.Felt, hash *big.Int, l int, sigArrFelt []*felt.Felt) error {
	callResp, err := clientv02.Call(context.Background(), rpc.FunctionCall{
		ContractAddress:    contractAddr,
		EntryPointSelector: utils.GetSelectorFromNameFelt("isValidSignature"),
		Calldata:           append([]*felt.Felt{utils.BigIntToFelt(hash), utils.Uint64ToFelt(uint64(l))}, sigArrFelt...),
	}, rpc.BlockID{Tag: "latest"})
	if err != nil {
		return fmt.Errorf("verifySigOld failed: %s", err)
	}
	if len(callResp) != 1 {
		return errors.New("verifySigOld failed")
	}
	//VALID
	if !strings.EqualFold(callResp[0].String(), "0x1") {
		return errors.New("verifySigOld failed not match")
	}
	return nil
}

func verifySigNew(clientv02 *rpc.Provider, contractAddr *felt.Felt, hash *big.Int, l int, sigArrFelt []*felt.Felt) error {
	callResp, err := clientv02.Call(context.Background(), rpc.FunctionCall{
		ContractAddress:    contractAddr,
		EntryPointSelector: utils.GetSelectorFromNameFelt("is_valid_signature"),
		Calldata:           append([]*felt.Felt{utils.BigIntToFelt(hash), utils.Uint64ToFelt(uint64(l))}, sigArrFelt...),
	}, rpc.BlockID{Tag: "latest"})
	if err != nil {
		return fmt.Errorf("verifySigNew failed: %s", err)
	}
	if len(callResp) != 1 {
		return errors.New("verifySigNew failed")
	}
	//VALID
	if !strings.EqualFold(callResp[0].String(), "0x56414c4944") {
		return errors.New("verifySigNew failed not match")
	}
	return nil
}

func truncate(raw string, targetL int) string {
	if len(raw) > targetL {
		return raw[:targetL]
	} else {
		return raw
	}
}

func (s StarkNetProcessor) VerifySigOld(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {

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
