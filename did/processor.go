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
package did

import "github.com/ontology-tech/ontlogin-sdk-go/modules"

type DidProcessor interface {
	VerifySig(did string, index int, msg []byte, sig []byte, pubkeyBytes []byte) error
	Sign(did string, index int, msg []byte) ([]byte, error)
	VerifyPresentation(presentation string, requiredTypes []*modules.VCFilter) error
	VerifyCredential(credential string, trustedDIDs []string) error
	GetCredentialJsons(presentation string) ([]string, error)
}
