package modules

type ClientHello struct {
	Ver             string           `json:"ver"`
	Type            string           `json:"type"`
	Name            string           `json:"name,omitempty"`
	Action          string           `json:"action"`
	ClientChallenge *ClientChallenge `json:"ClientChallenge"`
}

type ClientChallenge struct {
}

type ServerHello struct {
	Ver         string       `json:"ver"`
	Type        string       `json:"type"`
	Nonce       string       `json:"nonce"`
	Server      *ServerInfo  `json:"server"`
	Chain       []string     `json:"chain"`
	Alg         []string     `json:"alg"`
	VCFilters   []*VCFilter  `json:"VCFilters,omitempty"`
	ServerProof *ServerProof `json:"ServerProof,omitempty"`
	Extension   *Extension   `json:"extension,omitempty"`
}

type ServerInfo struct {
	Name               string `json:"name"`
	Icon               string `json:"icon,omitempty"`
	Url                string `json:"url"`
	Did                string `json:"did,omitempty"`
	VerificationMethod string `json:"verificationMethod,omitempty"`
}

type VCFilter struct {
	Type     string `json:"type"`
	Express  string `json:"express,omitempty"`
	Required bool   `json:"required"`
}

type ServerProof struct {
}

type Extension struct {
}

type ClientResponse struct {
	Ver   string   `json:"ver"`
	Type  string   `json:"type"`
	Did   string   `json:"did"`
	Proof *Proof   `json:"proof"`
	VPs   []string `json:"VPs"`
}

type Proof struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verificationMethod"`
	Created            string `json:"created"`
	Nonce              string `json:"nonce"`
	Value              string `json:"value"`
}

type ClientResponseMsg struct {
	Type    string           `json:"type"`
	Server  ServerInfoToSign `json:"server"`
	nonce   string           `json:"nonce"`
	Did     string           `json:"did"`
	Created string           `json:"created"`
}

type ServerInfoToSign struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Did  string `json:"did"`
}
