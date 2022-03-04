package awsauth

import (
	"context"
	"fmt"

	"github.com/hashicorp/consul/agent/consul/authmethod"
	"github.com/hashicorp/consul/agent/structs"
	iamauth "github.com/hashicorp/consul/internal/go-iam"
	"github.com/hashicorp/go-hclog"
)

const (
	authMethodType string = "aws-iam"

	IAMServerIDHeaderName  string = "X-Consul-IAM-ServerID"
	GetEntityMethodHeader  string = "X-Consul-IAM-GetEntity-Method"
	GetEntityURLHeader     string = "X-Consul-IAM-GetEntity-URL"
	GetEntityHeadersHeader string = "X-Consul-IAM-GetEntity-Headers"
	GetEntityBodyHeader    string = "X-Consul-IAM-GetEntity-Body"
)

func init() {
	// register this as an available auth method type
	authmethod.Register(authMethodType, func(logger hclog.Logger, method *structs.ACLAuthMethod) (authmethod.Validator, error) {
		v, err := NewValidator(logger, method)
		if err != nil {
			return nil, err
		}
		return v, nil
	})
}

type Config struct {
	// BoundIAMPrincipalARNs are the trusted AWS IAM principal ARNs that are permitted
	// to login to the auth method. These can be the exact ARNs or wildcards. Wildcards
	// are only supported if EnableUserDetails is true.
	BoundIAMPrincipalARNs []string `json:",omitempty"`

	// EnableIAMEntityDetails will fetch the IAM User or IAM Role details to include
	// in binding rules. Required if wildcard principal ARNs are used.
	EnableIAMEntityDetails bool `json:",omitempty"`

	// IAMEntityTags are the specific IAM User or IAM Role tags to include as selectable
	// fields in the binding rule attributes. Requires EnableUserDetails = true.
	IAMEntityTags []string `json:",omitempty"`

	// ServerIDHeaderValue adds a X-Consul-IAM-ServersID header to each AWS API request.
	// This helps protect against replay attacks.
	ServerIDHeaderValue string `json:",omitempty"`

	// MaxRetries is the maximum number of retries on AWS API requests for recoverable errors.
	MaxRetries int `json:",omitempty"`
	// IAMEndpoint is the AWS IAM endpoint where iam:GetRole or iam:GetUser requests will be sent.
	// Note that the Host header in a signed request cannot be changed.
	IAMEndpoint string `json:",omitempty"`
	// STSEndpoint is the AWS STS endpoint where sts:GetCallerIdentity requests will be sent.
	// Note that the Host header in a signed request cannot be changed.
	STSEndpoint string `json:",omitempty"`
	// STSRegion is the region for the AWS STS service. This should only be set if STSEndpoint
	// is set, and must match the region of the STSEndpoint.
	STSRegion string `json:",omitempty"`

	// AllowedSTSHeaderValues is a list of additional allowed headers on the sts:GetCallerIdentity
	// request in the bearer token. A default list of necessary headers is allowed in any case.
	AllowedSTSHeaderValues []string `json:",omitempty"`

	enterpriseConfig `mapstructure:",squash"`
}

func (c *Config) convertForLibrary() *iamauth.Config {
	return &iamauth.Config{
		BoundIAMPrincipalARNs:  c.BoundIAMPrincipalARNs,
		EnableIAMEntityDetails: c.EnableIAMEntityDetails,
		IAMEntityTags:          c.IAMEntityTags,
		ServerIDHeaderValue:    c.ServerIDHeaderValue,
		MaxRetries:             c.MaxRetries, // TODO: Vault uses -1 as default. Make this work somehow.
		IAMEndpoint:            c.IAMEndpoint,
		STSEndpoint:            c.STSEndpoint,
		STSRegion:              c.STSRegion,
		AllowedSTSHeaderValues: c.AllowedSTSHeaderValues,

		ServerIDHeaderName:     IAMServerIDHeaderName,
		GetEntityMethodHeader:  GetEntityMethodHeader,
		GetEntityURLHeader:     GetEntityURLHeader,
		GetEntityHeadersHeader: GetEntityHeadersHeader,
		GetEntityBodyHeader:    GetEntityBodyHeader,
	}
}

type Validator struct {
	name   string
	config *iamauth.Config
	logger hclog.Logger

	auth *iamauth.Authenticator
}

func NewValidator(logger hclog.Logger, method *structs.ACLAuthMethod) (*Validator, error) {
	if method.Type != authMethodType {
		return nil, fmt.Errorf("%q is not an AWS IAM auth method", method.Name)
	}

	var config Config
	if err := authmethod.ParseConfig(method.Config, &config); err != nil {
		return nil, err
	}
	iamConfig := config.convertForLibrary()

	auth, err := iamauth.NewAuthenticator(iamConfig, logger)
	if err != nil {
		return nil, err
	}

	return &Validator{
		name:   method.Name,
		config: iamConfig,
		logger: logger,
		auth:   auth,
	}, nil
}

// Name implements authmethod.Validator.
func (v *Validator) Name() string { return v.name }

// Stop implements authmethod.Validator.
func (v *Validator) Stop() {}

// ValidateLogin implements authmethod.Validator.
func (v *Validator) ValidateLogin(ctx context.Context, loginToken string) (*authmethod.Identity, error) {
	v.logger.Info("awsauth.ValidateLogin", "loginToken", loginToken)

	details, err := v.auth.Login(ctx, loginToken)
	if err != nil {
		return nil, err
	}

	return &authmethod.Identity{
		ProjectedVars: map[string]string{
			"entity_name": details.EntityName,
			"entity_id":   details.EntityId,
			"account_id":  details.AccountId,
		},
		SelectableFields: awsSelectableFields{
			EntityName: details.EntityName,
			EntityId:   details.EntityId,
			AccountId:  details.AccountId,
		},
		EnterpriseMeta: nil,
	}, nil
}

func (v *Validator) NewIdentity() *authmethod.Identity {
	v.logger.Info("awsauth.NewIdentity")

	return &authmethod.Identity{
		SelectableFields: &awsSelectableFields{},
		ProjectedVars: map[string]string{
			"entity_name": "",
			"entity_id":   "",
			"account_id":  "",
		},
	}
}

type awsSelectableFields struct {
	EntityName string `bexpr:"entity_arn"`
	EntityId   string `bexpr:"entity_name"`
	AccountId  string `bexpr:"account_id"`
}
