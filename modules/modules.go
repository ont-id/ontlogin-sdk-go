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
package modules

type ClientHello struct {
	Ver             string           `json:"ver"`
	Type            string           `json:"type"`
	Action          int              `json:"action"`
	ClientChallenge *ClientChallenge `json:"ClientChallenge,omitempty"`
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
	Type       string   `json:"type"`
	Express    []string `json:"express,omitempty"`
	TrustRoots []string `json:"trust_roots"`
	Required   bool     `json:"required"`
}

type ServerProof struct {
}

type Extension struct {
}

type ClientResponse struct {
	Ver   string   `json:"ver"`
	Type  string   `json:"type"`
	Did   string   `json:"did"`
	Nonce string   `json:"nonce"`
	Proof *Proof   `json:"proof"`
	VPs   []string `json:"VPs,omitempty"`
}

type Proof struct {
	Type               string `json:"type"`
	VerificationMethod string `json:"verificationMethod"`
	Created            uint64 `json:"created"`
	Value              string `json:"value"`
}

type ClientResponseMsg struct {
	Type    string           `json:"type"`
	Server  ServerInfoToSign `json:"server"`
	Nonce   string           `json:"nonce"`
	Did     string           `json:"did"`
	Created uint64           `json:"created"`
}

type ServerInfoToSign struct {
	Name string `json:"name"`
	Url  string `json:"url"`
	Did  string `json:"did,omitempty"`
}
