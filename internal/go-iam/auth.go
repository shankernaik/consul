package iamauth

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/go-secure-stdlib/strutil"
)

const (
	// Retry configuration
	retryWaitMin = 500 * time.Millisecond
	retryWaitMax = 30 * time.Second
)

type Authenticator struct {
	config *Config
	logger hclog.Logger
}

type IdentityDetails struct {
	EntityName string
	EntityId   string
	AccountId  string

	EntityPath string
	EntityTags map[string]string
	EntityArn  string
}

func NewAuthenticator(config *Config, logger hclog.Logger) (*Authenticator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &Authenticator{
		config: config,
		logger: logger,
	}, nil
}

func (a *Authenticator) Login(ctx context.Context, loginToken string) (*IdentityDetails, error) {
	token, err := NewBearerToken(loginToken, a.config)
	if err != nil {
		return nil, err
	}

	req, err := token.GetCallerIdentityRequest()
	if err != nil {
		return nil, err
	}
	a.logger.Info("aws auth method", "sts:GetCallerIdentity", req)

	callerIdentity, err := a.submitCallerIdentityRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	a.logger.Info("identity details", "callerIdentity", callerIdentity)

	entity, err := parseIamArn(callerIdentity.Arn)
	if err != nil {
		return nil, err
	}

	if err := a.validateCallerIdentity(entity); err != nil {
		return nil, err
	}

	return &IdentityDetails{
		EntityName: entity.FriendlyName, // TODO: parse the name from this
		EntityId:   callerIdentity.UserId,
		AccountId:  callerIdentity.Account,

		// TODO: Other fields from the role/user
	}, nil
}

// https://github.com/hashicorp/vault/blob/ba533d006f2244103648785ebfe8a9a9763d2b6e/builtin/credential/aws/path_login.go#L1321-L1361
// However, we do not support the unique id check.
func (a *Authenticator) validateCallerIdentity(entity *iamEntity) error {
	if strutil.StrListContains(a.config.BoundIAMPrincipalARNs, entity.canonicalArn()) {
		// Matches one of BoundIAMPrincipalARNs, so it is trusted
		return nil
	}
	// TODO: Wildcard match if Entity Details is enabled
	return fmt.Errorf("IAM principal %s is not trusted", entity.canonicalArn())
}

// https://github.com/hashicorp/vault/blob/b17e3256dde937a6248c9a2fa56206aac93d07de/builtin/credential/aws/path_login.go#L1636
func (a *Authenticator) submitCallerIdentityRequest(ctx context.Context, req *http.Request) (*GetCallerIdentityResult, error) {
	retryableReq, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, err
	}
	retryableReq = retryableReq.WithContext(ctx)
	client := cleanhttp.DefaultClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	retryingClient := &retryablehttp.Client{
		HTTPClient:   client,
		RetryWaitMin: retryWaitMin,
		RetryWaitMax: retryWaitMax,
		RetryMax:     a.config.MaxRetries,
		CheckRetry:   retryablehttp.DefaultRetryPolicy,
		Backoff:      retryablehttp.DefaultBackoff,
	}

	response, err := retryingClient.Do(retryableReq)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	if response != nil {
		defer response.Body.Close()
	}
	// Validate that the response type is XML
	if ct := response.Header.Get("Content-Type"); ct != "text/xml" {
		return nil, fmt.Errorf("body of GetCallerIdentity is invalid")
	}

	// we check for status code afterwards to also print out response body
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("received error code %d from STS: %s", response.StatusCode, string(responseBody))
	}
	callerIdentityResponse, err := parseGetCallerIdentityResponse(string(responseBody))
	if err != nil {
		return nil, fmt.Errorf("error parsing STS response")
	}

	if n := len(callerIdentityResponse.GetCallerIdentityResult); n != 1 {
		return nil, fmt.Errorf("received %d identities in STS response but expected 1", n)
	}

	return &callerIdentityResponse.GetCallerIdentityResult[0], nil
}

func ensureHeaderIsSigned(signedHeaders, headerToSign string) error {
	// Not doing a constant time compare here, the values aren't secret
	for _, header := range strings.Split(signedHeaders, ";") {
		if header == strings.ToLower(headerToSign) {
			return nil
		}
	}
	return fmt.Errorf("header wasn't signed")
}

// https://github.com/hashicorp/vault/blob/ba533d006f2244103648785ebfe8a9a9763d2b6e/builtin/credential/aws/path_login.go#L1625-L1634
func parseGetCallerIdentityResponse(response string) (GetCallerIdentityResponse, error) {
	result := GetCallerIdentityResponse{}
	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "<GetCallerIdentityResponse") && !strings.HasPrefix(response, "<?xml") {
		return result, fmt.Errorf("body of GetCallerIdentity is invalid")
	}
	decoder := xml.NewDecoder(strings.NewReader(response))
	err := decoder.Decode(&result)
	return result, err
}

type GetCallerIdentityResponse struct {
	XMLName                 xml.Name                  `xml:"GetCallerIdentityResponse"`
	GetCallerIdentityResult []GetCallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata        []ResponseMetadata        `xml:"ResponseMetadata"`
}

type GetCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account string `xml:"Account"`
}

type ResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

// https://github.com/hashicorp/vault/blob/ba533d006f2244103648785ebfe8a9a9763d2b6e/builtin/credential/aws/path_login.go#L1482-L1530
// However, instance profiles are not support in Consul.
func parseIamArn(iamArn string) (*iamEntity, error) {
	// iamArn should look like one of the following:
	// 1. arn:aws:iam::<account_id>:<entity_type>/<UserName>
	// 2. arn:aws:sts::<account_id>:assumed-role/<RoleName>/<RoleSessionName>
	// if we get something like 2, then we want to transform that back to what
	// most people would expect, which is arn:aws:iam::<account_id>:role/<RoleName>
	var entity iamEntity
	fullParts := strings.Split(iamArn, ":")
	if len(fullParts) != 6 {
		return nil, fmt.Errorf("unrecognized arn: contains %d colon-separated parts, expected 6", len(fullParts))
	}
	if fullParts[0] != "arn" {
		return nil, fmt.Errorf("unrecognized arn: does not begin with \"arn:\"")
	}
	// normally aws, but could be aws-cn or aws-us-gov
	entity.Partition = fullParts[1]
	if fullParts[2] != "iam" && fullParts[2] != "sts" {
		return nil, fmt.Errorf("unrecognized service: %v, not one of iam or sts", fullParts[2])
	}
	// fullParts[3] is the region, which doesn't matter for AWS IAM entities
	entity.AccountNumber = fullParts[4]
	// fullParts[5] would now be something like user/<UserName> or assumed-role/<RoleName>/<RoleSessionName>
	parts := strings.Split(fullParts[5], "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("unrecognized arn: %q contains fewer than 2 slash-separated parts", fullParts[5])
	}
	entity.Type = parts[0]
	entity.Path = strings.Join(parts[1:len(parts)-1], "/")
	entity.FriendlyName = parts[len(parts)-1]
	// now, entity.FriendlyName should either be <UserName> or <RoleName>
	switch entity.Type {
	case "assumed-role":
		// Check for three parts for assumed role ARNs
		if len(parts) < 3 {
			return nil, fmt.Errorf("unrecognized arn: %q contains fewer than 3 slash-separated parts", fullParts[5])
		}
		// Assumed roles don't have paths and have a slightly different format
		// parts[2] is <RoleSessionName>
		entity.Path = ""
		entity.FriendlyName = parts[1]
		entity.SessionInfo = parts[2]
	case "user":
	case "role":
	// case "instance-profile":
	default:
		return &iamEntity{}, fmt.Errorf("unrecognized principal type: %q", entity.Type)
	}
	return &entity, nil
}

// https://github.com/hashicorp/vault/blob/ba533d006f2244103648785ebfe8a9a9763d2b6e/builtin/credential/aws/path_login.go#L1722-L1744
type iamEntity struct {
	Partition     string
	AccountNumber string
	Type          string
	Path          string
	FriendlyName  string
	SessionInfo   string
}

// Returns a the canonical ARN for referring to an IAM entity
func (e *iamEntity) canonicalArn() string {
	entityType := e.Type
	// canonicalize "assumed-role" into "role"
	if entityType == "assumed-role" {
		entityType = "role"
	}
	// Annoyingly, the assumed-role entity type doesn't have the Path of the role which was assumed
	// So, we "canonicalize" it by just completely dropping the path. The other option would be to
	// make an AWS API call to look up the role by FriendlyName, which introduces more complexity to
	// code and test, and it also breaks backwards compatibility in an area where we would really want
	// it
	return fmt.Sprintf("arn:%s:iam::%s:%s/%s", e.Partition, e.AccountNumber, entityType, e.FriendlyName)
}
