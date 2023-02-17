package aptos

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"

	"io/ioutil"
	"net/http"
	"strings"
)

type AptosAccountResp struct {
	SeqNum  string `json:"sequence_number"`
	AuthKey string `json:"authentication_key"`
}

type AptosProcessor struct {
	restUrl string
	client  *http.Client
}

func NewAptosProcessor(restUrl string) *AptosProcessor {
	return &AptosProcessor{
		restUrl: restUrl,
		client:  new(http.Client),
	}

}

func (apt *AptosProcessor) VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error {
	if pubkeyBytes == nil {
		return fmt.Errorf("pubkeyBytes required")
	}
	aptAddr, err := getAptAddressFromDID(did)
	if err != nil {
		return err
	}

	authkey := SingleSignerAuthKey(pubkeyBytes)
	authkeystr := hex.EncodeToString(authkey[:])
	if !strings.EqualFold(hex.EncodeToString(authkey[:]), aptAddr) {

		authkeyOnchain, err := apt.GetAccountAuthKeyOnChain("0x" + aptAddr)
		if err != nil {
			return err
		}
		if !strings.EqualFold(authkeyOnchain, "0x"+authkeystr) {
			return fmt.Errorf(modules.ERR_INVALID_PUBKEY)
		}
	}

	pubkey := ed25519.PublicKey(pubkeyBytes)

	msgWithPrefix := append([]byte("APTOS\nmessage: "), msg...)
	msgWithPrefix = append(msgWithPrefix, []byte("\nnonce: 1")...)

	f := ed25519.Verify(pubkey, msgWithPrefix, sig)
	if !f {
		return fmt.Errorf(modules.ERR_INVALID_SIGNATURE)
	}

	return nil
}
func (apt *AptosProcessor) Sign(did string, index int, msg []byte) ([]byte, error) {
	return nil, nil
}
func (apt *AptosProcessor) VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error {
	return nil
}
func (apt *AptosProcessor) VerifyCredential(credential string, trustedDIDs []string) error {
	return nil
}
func (apt *AptosProcessor) GetCredentialJsons(presentation string) ([]string, error) {
	return nil, nil
}

// no "0x" prefix
func getAptAddressFromDID(did string) (string, error) {
	arr := strings.Split(did, ":")
	if len(arr) != 3 {
		return "", fmt.Errorf(modules.ERR_INVALID_DID_FORMAT)
	}
	if arr[1] != "apto" {
		return "", fmt.Errorf(modules.ERR_NOT_APT_DID)
	}
	return arr[2], nil
}
func SingleSignerAuthKey(publicKey []byte) [32]byte {
	return sha3.Sum256(append(publicKey[:], 0x00))
}

func (apt *AptosProcessor) GetAccountAuthKeyOnChain(address string) (string, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s", apt.restUrl, address)
	method := "GET"
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}
	res, err := apt.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	accountResp := &AptosAccountResp{}
	err = json.Unmarshal(body, accountResp)
	if err != nil {
		return "", err
	}
	return accountResp.AuthKey, nil

}
