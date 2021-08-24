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

package ont

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"strings"

	"github.com/ontio/ontology-crypto/keypair"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
	oacct "github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/signature"

	"github.com/ontology-tech/ontlogin-sdk-go/utils"
)

type DidPubkey struct {
	Id           string      `json:"id"`
	Type         string      `json:"type"`
	Controller   interface{} `json:"controller"`
	PublicKeyHex string      `json:"publicKeyHex"`
}

type OntResolver struct {
	sdk                     *ontology_go_sdk.OntologySdk
	acct                    *ontology_go_sdk.Account
	isDoubleDirectionVerify bool
}

func (o *OntResolver) VerifySig(did string, index int, msg []byte, sig []byte) error {

	pubkey, err := o.getDIDPubkey(did, index)
	if err != nil {
		return err
	}
	return signature.Verify(pubkey, msg, sig)
}

func (o *OntResolver) Sign(did string, index int, msg []byte) ([]byte, error) {

	singer := &oacct.Account{
		PrivateKey: o.acct.PrivateKey,
		PublicKey:  o.acct.PublicKey,
		Address:    o.acct.Address,
		SigScheme:  o.acct.SigScheme,
	}

	return signature.Sign(singer, msg)
}

func (o *OntResolver) VerifyPresentation(did string, index int, presentation string, requiredTypes []*modules.VCFilter) error {
	//1. verify singer
	err := o.sdk.Credential.VerifyJWTIssuerSignature(presentation)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature failed:%s", err.Error())
	}

	jwtPress, err := o.sdk.Credential.JWTPresentation2Json(presentation)
	if err != nil {
		return fmt.Errorf("JWTPresentation2Json failed:%s", err.Error())
	}

	//verify presentation proof
	for i := range jwtPress.Proof {
		_, err = o.sdk.Credential.VerifyPresentationProof(jwtPress, i)
		if err != nil {
			return fmt.Errorf("VerifyPresentationProof failed:%s", err.Error())
		}
	}
	//verify presentations
	credTypes := make([]string, 0)
	for _, cred := range jwtPress.VerifiableCredential {
		c, err := o.sdk.Credential.JsonCred2JWT(cred)
		if err != nil {
			return fmt.Errorf("JsonCred2JWT failed:%s", err.Error())
		}
		err = o.VerifyCredential(did, index, c, utils.GetTrustRoot(cred.Type, requiredTypes))
		if err != nil {
			return err
		}
		credTypes = append(credTypes, credTypes...)
	}
	if requiredTypes != nil {
		for _, required := range requiredTypes {
			if !required.Required {
				continue
			}
			f := false
			for _, ctype := range credTypes {
				if strings.EqualFold(ctype, required.Type) {
					f = true
					break
				}
			}
			if !f {
				return fmt.Errorf("required credential:%s is not existed", required)
			}
		}
	}
	return nil
}

func (o *OntResolver) VerifyCredential(did string, index int, credential string, trustedDIDs []string) error {
	//1. verify signer
	err := o.sdk.Credential.VerifyJWTIssuerSignature(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature failed:%s", err.Error())
	}

	//2. verify issuance date
	err = o.sdk.Credential.VerifyJWTIssuanceDate(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuanceDate failed:%s", err.Error())

	}

	//3. verify expiration date
	err = o.sdk.Credential.VerifyJWTExpirationDate(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTIssuerSignature failed:%s", err.Error())
	}

	//4. verify trusted issuer did
	err = o.sdk.Credential.VerifyJWTCredibleOntId(trustedDIDs, credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTCredibleOntId failed:%s", err.Error())
	}

	//4. verify status
	err = o.sdk.Credential.VerifyJWTStatus(credential)
	if err != nil {
		return fmt.Errorf("VerifyJWTStatus failed:%s", err.Error())
	}
	return nil
}

func (o *OntResolver) getDIDPubkey(did string, index int) (keypair.PublicKey, error) {

	if o.sdk.Native == nil || o.sdk.Native.OntId == nil {
		return nil, fmt.Errorf("ontsdk is nil")
	}

	pubKey, err := o.sdk.Native.OntId.GetPublicKeysJson(did)
	if err != nil {
		return nil, err
	}
	var pks []DidPubkey
	err = json.Unmarshal(pubKey, &pks)
	if err != nil {
		return nil, err
	}
	if len(pks) < index {
		return nil, fmt.Errorf("no public key found")
	}
	pk, err := hex.DecodeString(pks[index-1].PublicKeyHex)
	if err != nil {
		return nil, err
	}
	newpubkey, err := keypair.DeserializePublicKey(pk)
	if err != nil {
		return nil, err
	}
	return newpubkey, nil
}

func (o *OntResolver) GetCredentialJsons(presentation string) ([]string, error) {
	vp, err := o.sdk.Credential.JWTPresentation2Json(presentation)
	if err != nil {
		return nil, err
	}

	creds := make([]string, 0)
	for _, vc := range vp.VerifiableCredential {
		credjson, err := o.sdk.Credential.JsonCred2JWT(vc)
		if err != nil {
			return nil, err
		}
		creds = append(creds, credjson)
	}

	return creds, nil
}

func NewOntResolver(doubleDirection bool, endpointURL string, didContractAddr string, walletFile string, password string) (*OntResolver, error) {

	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress(endpointURL)

	res := &OntResolver{}
	res.isDoubleDirectionVerify = doubleDirection
	if doubleDirection {
		if len(didContractAddr) == 0 {
			return nil, fmt.Errorf("did contract should not be empty")
		}
		_, err := common.AddressFromHexString(didContractAddr)
		if err != nil {
			return nil, fmt.Errorf("did contract address %s is invalid!", didContractAddr)
		}
		sdk.SetCredContractAddress(didContractAddr)

		wallet, err := sdk.OpenWallet(walletFile)
		if err != nil {
			return nil, fmt.Errorf("open wallet failed! %s", err.Error())
		}
		acct, err := wallet.GetDefaultAccount([]byte(password))
		if err != nil {
			return nil, fmt.Errorf("get account failed! %s", err.Error())
		}
		res.acct = acct
	}

	res.sdk = sdk
	return res, nil
}
