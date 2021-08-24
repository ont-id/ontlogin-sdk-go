package utils

import (
	"github.com/ontology-tech/ontlogin-sdk-go/modules"
	"strings"
)

func GetTrustRoot(vcType []string, filters []*modules.VCFilter) []string {
	for _, filter := range filters {
		for _, t := range vcType {
			if strings.EqualFold(t, filter.Type) {
				return filter.TrustRoots
			}
		}

	}
	return nil
}
