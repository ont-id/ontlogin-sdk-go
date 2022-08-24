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
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ontology-tech/ontlogin-sdk-go/modules"
)

/// todo currently we don't query the did:etho:xxx from smart contract,
/// so we can only verify signature from the eth address
///

type EthProcessor struct {
}

func NewEthProcessor() *EthProcessor {
	return &EthProcessor{}
}

func (e EthProcessor) VerifySig(did string, index int, msg []byte, sig []byte) error {
	ethAddress, err := getEthAddressFromDID(did)
	if err != nil {
		return err
	}
	f := ETHVerifySig(ethAddress, sig, msg)
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

func ETHVerifySig(from string, sig []byte, msg []byte) bool {
	fromAddr := common.HexToAddress(from)

	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sig[64] != 0 || sig[64] != 1 {
		if sig[64] != 27 && sig[64] != 28 {
			return false
		}
		sig[64] -= 27
	}
	pubKey, err := crypto.SigToPub(EthSignHash(msg), sig)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*pubKey)

	return strings.EqualFold(fromAddr.Hex(), recoveredAddr.Hex())
}
func EthSignHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}
