/*
 * Copyright (C) 2021 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package eth

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ontology-tech/ontlogin-sdk-go/did"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"

	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

/// todo currently we don't query the did:etho:xxx from smart contract,
/// so we can only verify signature from the eth address
///

var (
	EIP712_DOMAIN  = "ontlogin"
	EIP712_VERSION = "v1.0.0"
)

type EthProcessor struct {
}

func NewEthProcessor() *EthProcessor {
	return &EthProcessor{}
}

func (e EthProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	ethAddress, err := getEthAddressFromDID(did)
	if err != nil {
		return err
	}
	f := ETHVerifySig(ethAddress, sig, msg, false)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}

	return nil
}
func (e EthProcessor) VerifySigEIP712(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte, data did.EIP712Msg) error {
	ethAddress, err := getEthAddressFromDID(did)
	if err != nil {
		return err
	}

	hash, err := GetEIP712SignHash(EIP712_DOMAIN, EIP712_VERSION, data)
	if err != nil {
		return err
	}
	f := ETHVerifySig(ethAddress, sig, hash, true)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}

	return nil
}

func (e EthProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	panic("implement me")
}

func (e EthProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	panic("implement me")
}

func (e EthProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	panic("implement me")
}

func (e EthProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	panic("implement me")
}

func getEthAddressFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "etho" {
		return "", fmt.Errorf(modules.ERR_NOT_ETH_DID)
	}
	return "0x" + arr[2], nil
}

func ETHVerifySig(from string, sig []byte, msg []byte, is712 bool) bool {
	fromAddr := common.HexToAddress(from)

	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sig[64] != 0 && sig[64] != 1 {
		if sig[64] != 27 && sig[64] != 28 {
			return false
		}
		sig[64] -= 27
	}

	msgbts := msg
	if !is712 {
		msgbts = EthSignHash(msg)
	}

	pubKey, err := crypto.SigToPub(msgbts, sig)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)
	fmt.Printf("recoveredAddr:%s, from:%s\n", recoveredAddr.Hex(), fromAddr.Hex())

	return strings.EqualFold(fromAddr.Hex(), recoveredAddr.Hex())
}
func EthSignHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// func GetEIP712SignHash(domainName string, domainVersion string, msg EIP712Msg) ([]byte, error) {
// 	var signerData = apitypes.TypedData{
// 		Types: apitypes.Types{
// 			"ClientResponseMsg": {
// 				{Name: "type", Type: "string"},
// 				{Name: "serverName", Type: "string"},
// 				{Name: "serverUrl", Type: "string"},
// 				{Name: "serverDid", Type: "string"},
// 				{Name: "nonce", Type: "string"},
// 				{Name: "did", Type: "string"},
// 				{Name: "created", Type: "uint256"},
// 			},
// 			"EIP712Domain": []apitypes.Type{
// 				{Name: "name", Type: "string"},
// 				{Name: "version", Type: "string"},
// 			},
// 		},
// 		PrimaryType: "ClientResponseMsg",
// 		Domain: apitypes.TypedDataDomain{
// 			Name:    "ontlogin",
// 			Version: "v1.0.0",
// 		},
// 		Message: apitypes.TypedDataMessage{
// 			"type":       "ClientResponse",
// 			"serverName": "orange_server",
// 			"serverUrl":  "https://www.orangeprotocol.io/",
// 			"serverDid":  "did:ont:AXdmdzbyf3WZKQzRtrNQwAR91ZxMUfhXkt",
// 			"nonce":      "12313123131124",
// 			"did":        "did:etho:6A426c1e07cCBA3401197Eb1E9EC8Fc6152dA239",
// 			"created":    math.NewHexOrDecimal256(int64(1715831360336)),
// 		},
// 	}

// 	hash, rawStr, err := apitypes.TypedDataAndHash(signerData)
// 	fmt.Printf("rawStr: %s\n", rawStr)
// 	fmt.Printf("hash: %s\n", hexutil.Encode(hash))
// 	return hash, err
// }

func GetEIP712SignHash(domainName string, domainVersion string, msg did.EIP712Msg) ([]byte, error) {
	var signerData = apitypes.TypedData{
		Types: apitypes.Types{
			"ClientResponseMsg": {
				{Name: "type", Type: "string"},
				{Name: "serverName", Type: "string"},
				{Name: "serverUrl", Type: "string"},
				{Name: "serverDid", Type: "string"},
				{Name: "nonce", Type: "string"},
				{Name: "did", Type: "string"},
				{Name: "created", Type: "uint256"},
			},
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
			},
		},
		PrimaryType: "ClientResponseMsg",
		Domain: apitypes.TypedDataDomain{
			Name:    domainName,
			Version: domainVersion,
		},
		Message: apitypes.TypedDataMessage{
			"type":       msg.Type,
			"serverName": msg.ServerName,
			"serverUrl":  msg.ServerURL,
			"serverDid":  msg.ServerDid,
			"nonce":      msg.Nonce,
			"did":        msg.Did,
			"created":    math.NewHexOrDecimal256(int64(1715831360336)),
		},
	}

	hash, rawStr, err := apitypes.TypedDataAndHash(signerData)
	fmt.Printf("rawStr: %s\n", rawStr)
	fmt.Printf("hash: %s\n", hexutil.Encode(hash))
	return hash, err
}
