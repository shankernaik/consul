package iamauth

import (
	"fmt"
	"strings"
)

type Config struct {
	// BoundIAMPrincipalARNs are the trusted AWS IAM principal ARNs that are
	// permitted to login. These can be the exact ARNs or wildcards. Wildcards
	// are only supported if EnableIAMEntityDetails is true.
	BoundIAMPrincipalARNs []string

	// EnableIAMEntityDetails will fetch the IAM User or IAM Role details to
	// include in binding rules. Required if wildcard principal ARNs are used.
	EnableIAMEntityDetails bool

	// TODO: I'm thinking this won't be explicitly needed here? We'll see.
	// IAMEntityTags are the specific IAM User or IAM Role tags to include as selectable
	// fields in the binding rule attributes. Requires EnableUserDetails = true.
	IAMEntityTags []string

	// TODO: Unfortunately, the existing awsutil.GenerateLoginData method,
	// uses a hardcoded header name, "X-Vault-AWS-IAM-ServerID", header.
	// We'd rather this header be "X-Consul-AWS-IAM-ServerID" but GenerateLoginData
	// signs the request, so we can modify the headers without resigning, and at that
	// point we need to re-implement the whole method.
	ServerIDHeaderValue string

	MaxRetries             int
	IAMEndpoint            string
	STSEndpoint            string
	STSRegion              string
	AllowedSTSHeaderValues []string

	// Customizable header names
	ServerIDHeaderName     string
	GetEntityMethodHeader  string
	GetEntityURLHeader     string
	GetEntityHeadersHeader string
	GetEntityBodyHeader    string
}

func (c *Config) Validate() error {
	if len(c.BoundIAMPrincipalARNs) == 0 {
		return fmt.Errorf("BoundIAMPrincipalARNs is required and must have at least 1 entry")
	}

	for _, arn := range c.BoundIAMPrincipalARNs {
		if strings.Contains(arn, "*") {
			if !c.EnableIAMEntityDetails {
				return fmt.Errorf("Must set EnableUserDetails=true to use wildcards in BoundIAMPrincipalARNs")
			}
		}
	}

	if len(c.IAMEntityTags) > 0 && !c.EnableIAMEntityDetails {
		return fmt.Errorf("Must set EnableUserDetails=true to use IAMUserTags")
	}

	// If server id header checking is enabled, we need the header name.
	if c.ServerIDHeaderValue != "" && c.ServerIDHeaderName == "" {
		return fmt.Errorf("IAMServerIDHeaderName must be configured to use IAMServerIDHeaderValue")
	}

	if c.EnableIAMEntityDetails && (c.GetEntityBodyHeader == "" ||
		c.GetEntityHeadersHeader == "" ||
		c.GetEntityMethodHeader == "" ||
		c.GetEntityURLHeader == "") {
		return fmt.Errorf("Must set all of GetEntityMethodHeader, GetEntityURLHeader, " +
			"GetEntityHeadersHeader, and GetEntityBodyHeader when EnabledIAMEntityDetails=true")
	}

	return nil
}

func (c *Config) iamEndpoint() string {
	if c.IAMEndpoint != "" {
		return c.IAMEndpoint
	}
	return defaultIAMEndpoint
}
