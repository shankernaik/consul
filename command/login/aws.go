package login

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"

	iamauth "github.com/hashicorp/consul/internal/go-iam"
)

// createAWSBearerToken discovers AWS credentials and formats a JSON-encoded, signed
// sts:GetCallerIdentity request. The JSON string is used as the bearer token string
// for the AWS auth method.
//
// If includeEntity is true, a signed iam:GetRole or iam:GetUser request is also
// included in the token.
func createAWSBearerToken(includeEntity bool) (string, error) {
	// Session loads creds from standard sources (env, shared file, EC2 metadata, ...)
	sess, err := session.NewSession()
	if err != nil {
		return "", err
	}
	if sess.Config.Region == nil || *sess.Config.Region == "" {
		return "", fmt.Errorf("AWS region is required (AWS_REGION)")
	}

	creds := sess.Config.Credentials
	if creds == nil {
		return "", fmt.Errorf("failed to discover AWS credentials")
	}

	loginData, err := iamauth.GenerateLoginData(creds, "", *sess.Config.Region, includeEntity, nil)
	if err != nil {
		return "", err
	}

	loginDataJson, err := json.Marshal(loginData)
	if err != nil {
		return "", err
	}

	return string(loginDataJson), err
}
