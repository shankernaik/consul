package awsauth

import "github.com/hashicorp/consul/agent/structs"

// TODO: Enterprise stuff
type enterpriseConfig struct{}

func enterpriseValidation(method *structs.ACLAuthMethod, config *Config) error {
	return nil
}

func (v *Validator) awsEntMetaFromFields(fields map[string]string) *structs.EnterpriseMeta {
	return nil
}
