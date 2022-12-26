package solana

import (
	"fmt"
	solana "github.com/gagliardetto/solana-go"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"strings"
)

type SolanaProcessor struct {
}

func NewSolanaProcessor() *SolanaProcessor { return &SolanaProcessor{} }

func (s SolanaProcessor) VerifySig(did string, index int, msg []byte, sig []byte) error {
	addr, err := getSolAddrFromDID(did)
	if err != nil {
		return err
	}
	pubkey, err := solana.PublicKeyFromBase58(addr)
	if err != nil {
		return err
	}
	solsig := solana.SignatureFromBytes(sig)

	f := pubkey.Verify(msg, solsig)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}

	return nil
}

func (s SolanaProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s SolanaProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	//TODO implement me
	panic("implement me")
}

func (s SolanaProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	//TODO implement me
	panic("implement me")
}

func (s SolanaProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}

func getSolAddrFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "solo" {
		return "", fmt.Errorf(modules.ERR_NOT_SOL_DID)
	}
	return arr[2], nil
}
