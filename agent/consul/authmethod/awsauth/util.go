package awsauth

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// https://github.com/hashicorp/vault/blob/057c67f969805a51e944898163aeff069d6a2e37/builtin/credential/aws/path_login.go#L1482
func parseArn(arnStr string) (*IAMArn, error) {
	// arn:aws:iam::<account_id>:<entity_type>/<UserName>
	parsedArn, err := arn.Parse(arnStr)
	if err != nil {
		return nil, err
	}

	if parsedArn.Service != "iam" && parsedArn.Service != "sts" {
		return nil, fmt.Errorf("unsupported arn %q: only 'iam' and 'sts' are supported", arnStr)
	}

	resourceParts := strings.Split(parsedArn.Resource, "/")
	if len(resourceParts) < 2 {
		return nil, fmt.Errorf("unsupported arn %q: resource '%s' must have two or more parts", arnStr, parsedArn.Resource)
	}

	result := &IAMArn{
		ARN:        parsedArn,
		EntityType: resourceParts[0],
	}

	switch resourceParts[0] {
	case "assumed-role":
		if len(resourceParts) != 3 {
			return nil, fmt.Errorf("unsupported arn %q: resource '%s' must have three parts for assumed roles", arnStr, parsedArn.Resource)
		}
		// "assumed-role/role/<session-id>"
		result.EntityPath = ""
		result.EntityFriendlyName = resourceParts[1]
		result.RoleSessionId = resourceParts[2]
	case "user", "role":
		//   "user/my-user"
		//   "user/<path>/my-user"
		//   "role/my-role"
		//   "role/<path>/my-role"
		result.EntityPath = strings.Join(resourceParts[1:len(resourceParts)-1], "/")
		result.EntityFriendlyName = resourceParts[len(resourceParts)-1]
	default:
		return nil, fmt.Errorf("unsupported arn %q: only 'user', 'role', or 'assumed-role' resource types are supported", arnStr)
	}

	return result, nil
}

type IAMArn struct {
	arn.ARN

	EntityType         string
	EntityPath         string
	EntityFriendlyName string

	// Only set for EntityType == "assumed-role"
	RoleSessionId string
}
