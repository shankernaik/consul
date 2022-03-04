package iamauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/go-hclog"
)

// GenerateLoginData populates the necessary data to send for the bearer token.
// https://github.com/hashicorp/go-secure-stdlib/blob/main/awsutil/generate_credentials.go#L232-L301
func GenerateLoginData(creds *credentials.Credentials, headerValue, region string, includeEntity bool, logger hclog.Logger) (map[string]interface{}, error) {

	// Use the credentials we've found to construct an STS session
	// TODO: Do we need this? Or can just assume the region from the credentials?
	// region, err := GetRegion(configuredRegion)
	//if err != nil {
	//	logger.Warn(fmt.Sprintf("defaulting region to %q due to %s", DefaultRegion, err.Error()))
	//	region = DefaultRegion
	//}
	stsSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &region,
			EndpointResolver: endpoints.ResolverFunc(stsSigningResolver),
		},
	})
	if err != nil {
		return nil, err
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	// Include the iam:GetRole or iam:GetUser request in headers
	if includeEntity {
		entityRequest, err := signEntityRequest(creds, headerValue, region, logger)
		if err != nil {
			return nil, err
		}

		headersJson, err := json.Marshal(entityRequest.HTTPRequest.Header)
		if err != nil {
			return nil, err
		}
		requestBody, err := ioutil.ReadAll(entityRequest.HTTPRequest.Body)
		if err != nil {
			return nil, err
		}

		// TODO: parameterize these header names
		stsRequest.HTTPRequest.Header.Add("X-Consul-IAM-GetEntity-Method", entityRequest.HTTPRequest.Method)
		stsRequest.HTTPRequest.Header.Add("X-Consul-IAM-GetEntity-URL", entityRequest.HTTPRequest.URL.String())
		stsRequest.HTTPRequest.Header.Add("X-Consul-IAM-GetEntity-Headers", string(headersJson))
		stsRequest.HTTPRequest.Header.Add("X-Consul-IAM-GetEntity-Body", string(requestBody))
	}

	// Inject the required auth header value, if supplied, and then sign the request including that header
	if headerValue != "" {
		stsRequest.HTTPRequest.Header.Add("X-Consul-IAM-ServerID", headerValue)
	}

	stsRequest.Sign()

	// Now extract out the relevant parts of the request
	headersJson, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, err
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"iam_http_request_method": stsRequest.HTTPRequest.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJson),
		"iam_request_body":        base64.StdEncoding.EncodeToString(requestBody),
	}, nil
}

// STS is a really weird service that used to only have global endpoints but now has regional endpoints as well.
// For backwards compatibility, even if you request a region other than us-east-1, it'll still sign for us-east-1.
// See, e.g., https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html#id_credentials_temp_enable-regions_writing_code
// So we have to shim in this EndpointResolver to force it to sign for the right region
func stsSigningResolver(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
	defaultEndpoint, err := endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
	if err != nil {
		return defaultEndpoint, err
	}
	defaultEndpoint.SigningRegion = region
	return defaultEndpoint, nil
}

func signEntityRequest(creds *credentials.Credentials, headerValue, region string, logger hclog.Logger) (*request.Request, error) {
	// TODO: duplicaated sesssion from GenerateLoginData
	stsSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials:      creds,
			Region:           &region,
			EndpointResolver: endpoints.ResolverFunc(stsSigningResolver),
		},
	})
	if err != nil {
		return nil, err
	}

	// We need to retrieve the IAM user or role for the iam:GetRole or iam:GetUser request.
	// GetCallerIdentity returns this and requires no permissions.
	svc := sts.New(stsSession)
	resp, err := svc.GetCallerIdentity(nil)
	if err != nil {
		return nil, err
	}

	ent, err := parseIamArn(*resp.Arn)
	if err != nil {
		return nil, err
	}

	iamSession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Credentials: creds,
			Region:      &region,
		},
	})
	if err != nil {
		return nil, err
	}
	iamSvc := iam.New(iamSession)

	var req *request.Request
	switch ent.Type {
	case "role", "assumed-role":
		req, _ = iamSvc.GetRoleRequest(&iam.GetRoleInput{RoleName: &ent.FriendlyName})
	case "user":
		req, _ = iamSvc.GetUserRequest(&iam.GetUserInput{UserName: &ent.FriendlyName})
	default:
		return nil, fmt.Errorf("entity %s is not an IAM role or IAM user", ent.Type)
	}

	// Inject the required auth header value, if supplied, and then sign the request including that header
	if headerValue != "" {
		req.HTTPRequest.Header.Add("X-Consul-IAM-ServerID", headerValue)
	}
	req.Sign()
	return req, nil
}
