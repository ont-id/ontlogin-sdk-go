package starkNet

import (
	"fmt"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"strings"
)

type StarkNetProcessor struct{}

func NewStarkNetProcessor() *StarkNetProcessor {
	return &StarkNetProcessor{}
}

func (s StarkNetProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	//TODO implement me
	panic("implement me")
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
	return arr[2], nil
}
