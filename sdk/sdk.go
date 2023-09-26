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
package sdk

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"strconv"
	"strings"

	"github.com/ontology-tech/ontlogin-sdk-go/did"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
)

type SDKConfig struct {
	Chain      []string
	Alg        []string
	ServerInfo *modules.ServerInfo
	VCFilters  map[int][]*modules.VCFilter
}

type OntLoginSdk struct {
	didProcessors map[string]did.DidProcessor
	conf          *SDKConfig
	//this function should generate and save a random nonce with action for client
	genRandomNonceFunc func(int) string
	//this function get action by nonce
	getActionByNonce func(string) (int, error)
}

func NewOntLoginSdk(conf *SDKConfig, processors map[string]did.DidProcessor, nonceFunc func(int) string, getActionByNonce func(string) (int, error)) (*OntLoginSdk, error) {
	return &OntLoginSdk{
		didProcessors:      processors,
		conf:               conf,
		genRandomNonceFunc: nonceFunc,
		getActionByNonce:   getActionByNonce,
	}, nil
}

func (s *OntLoginSdk) GetDIDChain(did string) (string, error) {
	tmpArr := strings.Split(did, ":")
	if len(tmpArr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if tmpArr[1] == "etho" {
		return "eth", nil
	}
	if tmpArr[1] == "solo" {
		return "solana", nil
	}
	if tmpArr[1] == "apto" {
		return "aptos", nil
	}
	if tmpArr[1] == "suio" {
		return "sui", nil
	}
	if tmpArr[1] == "trono" {
		return "tron", nil
	}

	return tmpArr[1], nil
}

func (s *OntLoginSdk) GenerateChallenge(req *modules.ClientHello) (*modules.ServerHello, error) {

	//1. validate req
	if err := s.validateClientHello(req); err != nil {
		return nil, err
	}
	//2. generate uuid
	uuid := s.genRandomNonceFunc(req.Action)

	res := &modules.ServerHello{}
	res.Ver = modules.SYS_VER
	res.Type = modules.TYPE_SERVER_HELLO
	res.Nonce = uuid
	res.Server = s.conf.ServerInfo
	res.Chain = s.conf.Chain
	res.Alg = s.conf.Alg

	if s.conf.VCFilters != nil && s.conf.VCFilters[req.Action] != nil {
		res.VCFilters = s.conf.VCFilters[req.Action]
	}
	//serverproof
	//extension
	return res, nil
}

func (s *OntLoginSdk) GetCredentialJson(chain, presentation string) ([]string, error) {
	processor, ok := s.didProcessors[chain]
	if !ok {
		return nil, fmt.Errorf(modules.ERR_CHAIN_NOT_SUPPORTED)
	}

	return processor.GetCredentialJsons(presentation)
}

func (s *OntLoginSdk) ValidateClientResponse(res *modules.ClientResponse) error {

	//1. validate res
	if err := s.validateClientResponse(res); err != nil {
		return err
	}

	did, index, err := getDIDKeyAndIndex(res.Proof.VerificationMethod)
	if !strings.EqualFold(did, res.Did) {
		return fmt.Errorf(modules.ERR_DID_NOT_MATCH)
	}
	chain, err := s.GetDIDChain(did)
	if err != nil {
		return err
	}
	action, err := s.getActionByNonce(res.Nonce)
	if err != nil {
		return fmt.Errorf(modules.ERR_NONCE_IS_NOT_EXIST)
	}
	msg := &modules.ClientResponseMsg{
		Type: res.Type,
		Server: modules.ServerInfoToSign{
			Name: s.conf.ServerInfo.Name,
			Url:  s.conf.ServerInfo.Url,
			Did:  s.conf.ServerInfo.Did,
		},
		Nonce:   res.Nonce,
		Did:     did,
		Created: res.Proof.Created,
	}
	v := res.Proof.Value
	if strings.HasPrefix(res.Proof.Value, "0x") {
		v = strings.ReplaceAll(res.Proof.Value, "0x", "")
	}
	sigdata, err := hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf(modules.ERR_DECODE_SIG)
	}
	dataToSign, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf(modules.ERR_MARSHAL_MSG)
	}

	processor, ok := s.didProcessors[chain]
	if !ok {
		return fmt.Errorf(modules.ERR_CHAIN_NOT_SUPPORTED)
	}
	var pubkeybts []byte
	if len(res.Pubkey) > 0 {
		if strings.HasPrefix(res.Pubkey, "0x") {
			pubkeybts, err = hexutil.Decode(res.Pubkey)
			if err != nil {
				return fmt.Errorf(modules.ERR_INVALID_PUBKEY)
			}
		} else {
			pubkeybts, err = hex.DecodeString(res.Pubkey)
			if err != nil {
				return fmt.Errorf(modules.ERR_INVALID_PUBKEY)
			}
		}
	}
	if err = processor.VerifySig(did, index, dataToSign, sigdata, pubkeybts); err != nil {
		return err
	}

	//verify presentation
	if res.VPs != nil && len(res.VPs) > 0 {
		requiredTypes := s.conf.VCFilters[action]
		for _, vp := range res.VPs {
			if err = processor.VerifyPresentation(vp, requiredTypes); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *OntLoginSdk) validateClientHello(req *modules.ClientHello) error {

	if !strings.EqualFold(req.Ver, modules.SYS_VER) {
		return fmt.Errorf(modules.ERR_WRONG_VERSION)
	}
	if !strings.EqualFold(req.Type, modules.TYPE_CLIENT_HELLO) {
		return fmt.Errorf(modules.ERR_TYPE_NOT_SUPPORTED)
	}
	if req.Action != modules.ACTION_AUTHORIZATION && req.Action != modules.ACTION_CERTIFICATION {
		return fmt.Errorf(modules.ERR_ACTION_NOT_SUPPORTED)
	}

	return nil
}

func (s *OntLoginSdk) validateClientResponse(response *modules.ClientResponse) error {
	if !strings.EqualFold(response.Ver, modules.SYS_VER) {
		return fmt.Errorf(modules.ERR_WRONG_VERSION)
	}
	if !strings.EqualFold(response.Type, modules.TYPE_CLIENT_RESPONSE) {
		return fmt.Errorf(modules.ERR_TYPE_NOT_SUPPORTED)
	}
	return nil
}

func getDIDKeyAndIndex(verifymethod string) (string, int, error) {
	tmpArr := strings.Split(verifymethod, "#")
	if len(tmpArr) != 2 {
		return "", 0, fmt.Errorf(modules.ERR_VERIFYMETHOD_FORMAT_INVALID)
	}
	keyArr := strings.Split(tmpArr[1], "-")
	if len(keyArr) != 2 {
		return "", 0, fmt.Errorf(modules.ERR_VERIFYMETHOD_FORMAT_INVALID)
	}
	idx, err := strconv.Atoi(keyArr[1])
	return tmpArr[0], idx, err
}
