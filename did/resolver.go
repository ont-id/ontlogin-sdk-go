package did

type DidResolver interface {
	//GetPubkeyString(did string ,index int)(string,error)
	VerifySig(did string, index int, msg []byte, sig []byte) error
	Sign(did string, index int, msg []byte) ([]byte, error)
	VerifyPresentation(did string, index int, presentation string, trustedDIDs []string, requiredTypes []string) error
	VerifyCredential(did string, index int, credential string, trustedDIDs []string) error
	GetCredentialJsons(presentation string)([]string,error)
}
