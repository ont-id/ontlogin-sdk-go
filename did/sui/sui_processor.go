package sui

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/fardream/go-bcs/bcs"
	"github.com/ontology-tech/ontlogin-sdk-go/did/sui/sui_types"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"

	"strings"
)

const (
	ADDRESS_LENGTH = 64
)

type SuiProcessor struct{}

func NewSuiProcessor() *SuiProcessor {
	return &SuiProcessor{}
}

func (s SuiProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	if pubkeyBytes == nil {
		return fmt.Errorf("pubkeyBytes required")
	}
	suiAddr, err := getSuiAddrFromDID(did)
	if err != nil {
		return err
	}
	tmp := []byte{0}
	tmp = append(tmp, pubkeyBytes...)
	addrBytes := blake2b.Sum256(tmp)
	address := hex.EncodeToString(addrBytes[:])[:ADDRESS_LENGTH]

	if !strings.EqualFold(suiAddr, address) {
		return fmt.Errorf(modules.ERR_INVALID_PUBKEY)
	}
	pubkey := ed25519.PublicKey(pubkeyBytes)

	msgBuffer := bytes.NewBuffer([]byte{})
	msgEncode := bcs.NewEncoder(msgBuffer)
	err = msgEncode.Encode(msg)
	if err != nil {
		return err
	}
	value := sui_types.NewIntentMessage(sui_types.Intent{
		Scope: sui_types.IntentScope{
			PersonalMessage: &sui_types.EmptyEnum{},
		},
		Version: sui_types.IntentVersion{
			V0: &sui_types.EmptyEnum{},
		},
		AppId: sui_types.AppId{
			Sui: &sui_types.EmptyEnum{},
		},
	}, sui_types.Base64Data(msgBuffer.Bytes()))

	message, err := bcs.Marshal(value)
	if err != nil {
		return err
	}
	hash := blake2b.Sum256(message)
	f := ed25519.Verify(pubkey, hash[:], sig)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}
	return nil
}

func (s SuiProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s SuiProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	//TODO implement me
	panic("implement me")
}

func (s SuiProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	//TODO implement me
	panic("implement me")
}

func (s SuiProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func getSuiAddrFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "suio" {
		return "", fmt.Errorf(modules.ERR_NOT_SOL_DID)
	}
	return arr[2], nil
}
