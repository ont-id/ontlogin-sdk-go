package sdk

import (
	"ontlogin-sdk-go/did"
	"ontlogin-sdk-go/did/ont"
	"ontlogin-sdk-go/modules"
	"testing"

	"github.com/stretchr/testify/assert"
)

func initTestEnv() *OntLoginSdk {
	conf := &SDKConfig{
		Chain: []string{"ont"},
		Alg:   []string{"ES256"},
		ServerInfo: &modules.ServerInfo{
			Name:               "testServcer",
			Icon:               "http://somepic.jpg",
			Url:                "https://ont.io",
			Did:                "did:ont:sampletest",
			VerificationMethod: "",
		},
		Vcfilters: []*modules.VCFilter{
			{Type: "EmailCredential", Required: true},
		},
		TrustedDIDs: []string{"did:ont:sampleissuer"},
	}

	resolvers := make(map[string]did.DidResolver)
	ontresolver, err := ont.NewOntResolver(false, "http://polaris2.ont.io:20336", "52df370680de17bc5d4262c446f102a0ee0d6312", "./wallet.dat", "123456")
	if err != nil {
		panic(err)
	}
	resolvers["ont"] = ontresolver
	loginsdk, err := NewOntLoginSdk(conf, resolvers, func() string {
		return "random string"
	}, func(s string) error {
		return nil
	})
	if err != nil {
		panic(err)
	}
	return loginsdk

}

func TestOntLoginSdk_GetDIDChain(t *testing.T) {
	olsdk := initTestEnv()
	chain, err := olsdk.GetDIDChain("did:ont:testdid")
	assert.Nil(t, err)
	assert.Equal(t, chain, "ont")
}

func TestOntLoginSdk_GenerateChallenge(t *testing.T) {
	olsdk := initTestEnv()
	olsdk.GenerateChallenge()
}
