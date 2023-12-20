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

package btc

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"strings"

	"github.com/ontology-tech/ontlogin-sdk-go/modules"
)

/// todo currently we don't query the did:etho:xxx from smart contract,
/// so we can only verify signature from the eth address
///

type BtcProcessor struct {
}

func NewBtcProcessor() *BtcProcessor {
	return &BtcProcessor{}
}

func (e BtcProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	f := BTCVerifySig("", sig, msg, pubkeyBytes)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}
	return nil
}

func (e BtcProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	panic("implement me")
}

func (e BtcProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	panic("implement me")
}

func (e BtcProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	panic("implement me")
}

func (e BtcProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	panic("implement me")
}

func getBtcAddressFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "btco" {
		return "", fmt.Errorf(modules.ERR_NOT_ETH_DID)
	}
	return "0x" + arr[2], nil
}

const messageSignatureHeader = "Bitcoin Signed Message:\n"

func BTCVerifySig(from string, sig []byte, msg, pubkeyBytes []byte) bool {
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, messageSignatureHeader)
	wire.WriteVarString(&buf, 0, string(msg))
	messageHash := chainhash.DoubleHashB(buf.Bytes())
	pk, _, err := ecdsa.RecoverCompact(sig, messageHash)
	if err != nil || pk == nil {
		return false
	}
	return bytes.Equal(pubkeyBytes, pk.SerializeCompressed())
}
