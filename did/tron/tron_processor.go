package tron

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	tron "github.com/fbsobreira/gotron-sdk/pkg/address"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"strings"
)

type TronProcessor struct{}

func (t TronProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	//sig := hexutil.MustDecode(sigHex)
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sig[64] != 27 && sig[64] != 28 {
		return fmt.Errorf("invalid sig")
	}
	sig[64] -= 27
	pubKey, err := crypto.SigToPub(TronSignHash(msg), sig)
	if err != nil {
		return fmt.Errorf("invalid pubkey")
	}
	inputAddr, err := getTronAddressFromDID(did)
	if err != nil {
		return err
	}

	addr := tron.PubkeyToAddress(*pubKey)
	f := strings.EqualFold(addr.String(), inputAddr)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}
	return nil
}

func (t TronProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (t TronProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	//TODO implement me
	panic("implement me")
}

func (t TronProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	//TODO implement me
	panic("implement me")
}

func (t TronProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	//TODO implement me
	panic("implement me")
}
func TronSignHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19TRON Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}
func getTronAddressFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "trono" {
		return "", fmt.Errorf(modules.ERR_NOT_ETH_DID)
	}
	return arr[2], nil
}
