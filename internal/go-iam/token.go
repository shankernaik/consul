package iamauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/strutil"
)

const (
	amzHeaderPrefix    = "X-Amz-"
	defaultIAMEndpoint = "https://iam.amazonaws.com"
	defaultSTSEndpoint = "https://sts.amazonaws.com"
)

var defaultAllowedSTSRequestHeaders = []string{
	"X-Amz-Algorithm",
	"X-Amz-Content-Sha256",
	"X-Amz-Credential",
	"X-Amz-Date",
	"X-Amz-Security-Token",
	"X-Amz-Signature",
	"X-Amz-SignedHeaders",
}

// BearerToken is a login "token" for an IAM auth method. It is a signed
// sts:GetCallerIdentity request in JSON format. Optionally, it can include a
// signed embedded iam:GetRole or iam:GetUser request in the headers.
type BearerToken struct {
	config *Config

	GetCallerIdentityMethod string
	GetCallerIdentityURL    string
	GetCallerIdentityHeader http.Header
	GetCallerIdentityBody   string

	parsedUrl *url.URL
}

var _ json.Unmarshaler = (*BearerToken)(nil)

func NewBearerToken(loginToken string, config *Config) (*BearerToken, error) {
	token := &BearerToken{config: config}
	if err := json.Unmarshal([]byte(loginToken), &token); err != nil {
		return nil, err
	}
	if err := token.validate(); err != nil {
		return nil, err
	}
	return token, nil
}

// https://github.com/hashicorp/vault/blob/b17e3256dde937a6248c9a2fa56206aac93d07de/builtin/credential/aws/path_login.go#L1178
func (t *BearerToken) validate() error {
	if t.GetCallerIdentityMethod != "POST" {
		return fmt.Errorf("iam_http_request_method must be POST")
	}
	if err := t.validateGetCallerIdentityBody(); err != nil {
		return err
	}
	if err := t.validateServerIDHeader(); err != nil {
		return err
	}
	if err := t.validateAllowedSTSHeaderValues(); err != nil {
		return err
	}
	return nil
}

// https://github.com/hashicorp/vault/blob/b17e3256dde937a6248c9a2fa56206aac93d07de/builtin/credential/aws/path_login.go#L1439
func (t *BearerToken) validateGetCallerIdentityBody() error {
	qs, err := url.ParseQuery(t.GetCallerIdentityBody)
	if err != nil {
		return err
	}
	for k, v := range qs {
		switch k {
		case "Action":
			if len(v) != 1 || v[0] != "GetCallerIdentity" {
				return fmt.Errorf("iam_request_body must have 'Action=GetCallerIdentity'")
			}
		case "Version":
		// Will assume for now that future versions don't change
		// the semantics
		default:
			// Not expecting any other values
			return fmt.Errorf("iam_request_body contains unexpected values")
		}
	}
	return nil
}

// https://github.com/hashicorp/vault/blob/b17e3256dde937a6248c9a2fa56206aac93d07de/builtin/credential/aws/path_login.go#L1532
func (t *BearerToken) validateServerIDHeader() error {
	requiredHeaderValue := t.config.ServerIDHeaderValue
	if requiredHeaderValue == "" {
		// Not configured, so nothing to check.
		return nil
	}
	iamServerIdHeader := t.config.ServerIDHeaderName
	headers := t.GetCallerIdentityHeader

	providedValue := ""
	for k, v := range headers {
		if strings.EqualFold(iamServerIdHeader, k) {
			providedValue = strings.Join(v, ",")
			break
		}
	}
	if providedValue == "" {
		return fmt.Errorf("missing header %q", iamServerIdHeader)
	}

	// NOT doing a constant time compare here since the value is NOT intended to be secret
	if providedValue != requiredHeaderValue {
		return fmt.Errorf("expected %q but got %q", requiredHeaderValue, providedValue)
	}

	if authzHeaders, ok := headers["Authorization"]; ok {
		// authzHeader looks like AWS4-HMAC-SHA256 Credential=AKI..., SignedHeaders=host;x-amz-date;x-vault-awsiam-id, Signature=...
		// We need to extract out the SignedHeaders
		re := regexp.MustCompile(".*SignedHeaders=([^,]+)")
		authzHeader := strings.Join(authzHeaders, ",")
		matches := re.FindSubmatch([]byte(authzHeader))
		if len(matches) < 1 {
			return fmt.Errorf("vault header wasn't signed")
		}
		if len(matches) > 2 {
			return fmt.Errorf("found multiple SignedHeaders components")
		}
		signedHeaders := string(matches[1])
		return ensureHeaderIsSigned(signedHeaders, iamServerIdHeader)
	}
	// TODO: If we support GET requests, then we need to parse the X-Amz-SignedHeaders
	// argument out of the query string and search in there for the header value
	return fmt.Errorf("missing Authorization header")
}

// https://github.com/hashicorp/vault/blob/861454e0ed1390d67ddaf1a53c1798e5e291728c/builtin/credential/aws/path_config_client.go#L349
func (t *BearerToken) validateAllowedSTSHeaderValues() error {
	// TODO: Need a version of StrListContains here.
	for k := range t.GetCallerIdentityHeader {
		h := textproto.CanonicalMIMEHeaderKey(k)
		if strings.HasPrefix(h, amzHeaderPrefix) &&
			!strutil.StrListContains(defaultAllowedSTSRequestHeaders, h) &&
			!strutil.StrListContains(t.config.AllowedSTSHeaderValues, h) {
			return fmt.Errorf("invalid request header: %s", h)
		}
	}
	return nil
}

// UnmarshalJSON unmarshals the bearer token details which contains an HTTP
// request (a signed sts:GetCallerIdentity request).
func (t *BearerToken) UnmarshalJSON(data []byte) error {
	// TODO: remove this intermediate struct
	var rawData struct {
		Method        string `json:"iam_http_request_method"`
		UrlBase64     string `json:"iam_request_url"`
		HeadersBase64 string `json:"iam_request_headers"`
		BodyBase64    string `json:"iam_request_body"`
	}

	if err := json.Unmarshal(data, &rawData); err != nil {
		return err
	}

	rawUrl, err := base64.StdEncoding.DecodeString(rawData.UrlBase64)
	if err != nil {
		return err
	}

	headersJson, err := base64.StdEncoding.DecodeString(rawData.HeadersBase64)
	if err != nil {
		return err
	}

	var headers http.Header
	// This is a JSON-string in JSON
	if err := json.Unmarshal(headersJson, &headers); err != nil {
		return err
	}

	body, err := base64.StdEncoding.DecodeString(rawData.BodyBase64)
	if err != nil {
		return err
	}

	parsedUrl, err := url.Parse(t.GetCallerIdentityURL)
	if err != nil {
		return err
	}

	t.GetCallerIdentityMethod = rawData.Method
	t.GetCallerIdentityBody = string(body)
	t.GetCallerIdentityHeader = headers
	t.GetCallerIdentityURL = string(rawUrl)
	t.parsedUrl = parsedUrl
	return nil
}

// GetCallerIdentityRequest returns the sts:GetCallerIdentity request decoded
// from the bearer token.
func (t *BearerToken) GetCallerIdentityRequest() (*http.Request, error) {
	// NOTE: We need to ensure we're calling STS, instead of acting as an unintended network proxy
	// The protection against this is that this method will only call the endpoint specified in the
	// client config (defaulting to sts.amazonaws.com), so it would require an admin to override
	// the endpoint to talk to alternate web addresses
	endpoint := defaultSTSEndpoint
	if t.config.STSEndpoint != "" {
		endpoint = t.config.STSEndpoint
	}

	// Support sending to region-specific STS endpoints, but preserve the Host
	// header and URI, which are signed and cannot be modified.
	//
	// There's a deeper explanation of this in the Vault source code:
	// https://github.com/hashicorp/vault/blob/b17e3256dde937a6248c9a2fa56206aac93d07de/builtin/credential/aws/path_login.go#L1569
	targetUrl := fmt.Sprintf("%s/%s", endpoint, t.parsedUrl.RequestURI())
	request, err := http.NewRequest(t.GetCallerIdentityMethod, targetUrl, strings.NewReader(t.GetCallerIdentityBody))
	if err != nil {
		return nil, err
	}
	request.Host = t.parsedUrl.Host
	for k, vals := range t.GetCallerIdentityHeader {
		for _, val := range vals {
			request.Header.Add(k, val)
		}
	}
	return request, nil
}

// GetEntityRequest returns the iam:GetUser or iam:GetRole request from the the
// request details, if present, embedded in the headers of the
// sts:GetCallerIdentity request.
func (t *BearerToken) GetEntityRequest() (*http.Request, error) {
	method, err := t.getHeader(t.config.GetEntityMethodHeader)
	if err != nil {
		return nil, err
	}

	url, err := t.getHeader(t.config.GetEntityURLHeader)
	if err != nil {
		return nil, err
	}

	headerJson, err := t.getHeader(t.config.GetEntityHeadersHeader)
	if err != nil {
		return nil, err
	}

	var header http.Header
	if err := json.Unmarshal([]byte(headerJson), &header); err != nil {
		return nil, err
	}

	body, err := t.getHeader(t.config.GetEntityBodyHeader)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = header

	return req, nil
}

// getHeader returns the header from s.GetCallerIdentityHeader, or an error if
// the header is not found or is not a single value.
func (t *BearerToken) getHeader(name string) (string, error) {
	values, ok := t.GetCallerIdentityHeader[name]
	if !ok {
		return "", fmt.Errorf("missing header %q", name)
	}
	if len(values) != 1 {
		return "", fmt.Errorf("invalid value for header %q (expected 1 item)", name)
	}
	return values[0], nil
}
