// Package awssts exchanges the long-lived access key stored in the Vault for
// temporary credentials from the AWS Security Token Service (STS).
package awssts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Keeper-Security/aws-credential-process/internal/vault"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

const (
	// SessionName identifies sessions created by this tool in CloudTrail. It
	// is used as the federated user name and the role session name, so it
	// must fit GetFederationToken's 2-32 character limit.
	SessionName = "keeper-aws-credential-process"

	// MinDuration and MaxDuration are the limits STS enforces for
	// GetSessionToken and GetFederationToken.
	MinDuration = 15 * time.Minute
	MaxDuration = 36 * time.Hour

	// MaxRoleDuration is the highest maximum session duration a role can be
	// configured with. The role's own setting may be lower; STS rejects the
	// request if it is.
	MaxRoleDuration = 12 * time.Hour

	defaultRegion = "us-east-1"
)

// API is the subset of the STS client used here, so tests can substitute it.
type API interface {
	GetSessionToken(context.Context, *sts.GetSessionTokenInput, ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error)
	GetFederationToken(context.Context, *sts.GetFederationTokenInput, ...func(*sts.Options)) (*sts.GetFederationTokenOutput, error)
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// Options selects the STS call and its parameters.
//
//   - RoleARN set: AssumeRole, with Policy as an optional session policy.
//   - Policy set without RoleARN: GetFederationToken, scoped by Policy.
//   - Neither: GetSessionToken.
type Options struct {
	RoleARN  string
	Duration time.Duration // 0 uses the STS default for the call.
	Policy   string        // Compacted JSON policy document, or "".
}

// Validate checks Duration against the limits of the STS call Options selects.
func (o Options) Validate() error {
	if o.Duration == 0 {
		return nil
	}
	if o.Duration%time.Second != 0 {
		return fmt.Errorf("--duration must be a whole number of seconds, got %s", o.Duration)
	}
	max := MaxDuration
	if o.RoleARN != "" {
		max = MaxRoleDuration
	}
	if o.Duration < MinDuration || o.Duration > max {
		return fmt.Errorf("--duration must be between %s and %s, got %s", MinDuration, max, o.Duration)
	}
	return nil
}

// ReadPolicy reads a JSON policy document from path and returns it compacted,
// since STS limits the packed size of session policies.
func ReadPolicy(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading policy file: %w", err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return "", fmt.Errorf("policy file %s is not valid JSON: %w", path, err)
	}
	return buf.String(), nil
}

// Region returns the region for STS requests: AWS_REGION, then
// AWS_DEFAULT_REGION, then us-east-1.
func Region() string {
	for _, name := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if r := os.Getenv(name); r != "" {
			return r
		}
	}
	return defaultRegion
}

// NewClient returns an STS client signed with the given static key. It is
// built directly rather than from the shared AWS config, which would resolve
// the profile's credential_process and call this executable again.
func NewClient(accessKeyID, secretAccessKey string, optFns ...func(*sts.Options)) *sts.Client {
	return sts.New(sts.Options{
		Region:      Region(),
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	}, optFns...)
}

// GetCredentials calls the STS operation selected by opts and returns the
// temporary credentials in credential_process form.
func GetCredentials(ctx context.Context, client API, opts Options) (*vault.Credential, error) {
	var duration *int32
	if opts.Duration > 0 {
		duration = aws.Int32(int32(opts.Duration / time.Second))
	}
	var policy *string
	if opts.Policy != "" {
		policy = aws.String(opts.Policy)
	}

	var creds *types.Credentials
	switch {
	case opts.RoleARN != "":
		out, err := client.AssumeRole(ctx, &sts.AssumeRoleInput{
			RoleArn:         aws.String(opts.RoleARN),
			RoleSessionName: aws.String(SessionName),
			DurationSeconds: duration,
			Policy:          policy,
		})
		if err != nil {
			return nil, fmt.Errorf("sts AssumeRole: %w", err)
		}
		creds = out.Credentials
	case policy != nil:
		out, err := client.GetFederationToken(ctx, &sts.GetFederationTokenInput{
			Name:            aws.String(SessionName),
			DurationSeconds: duration,
			Policy:          policy,
		})
		if err != nil {
			return nil, fmt.Errorf("sts GetFederationToken: %w", err)
		}
		creds = out.Credentials
	default:
		out, err := client.GetSessionToken(ctx, &sts.GetSessionTokenInput{
			DurationSeconds: duration,
		})
		if err != nil {
			return nil, fmt.Errorf("sts GetSessionToken: %w", err)
		}
		creds = out.Credentials
	}

	if creds == nil {
		return nil, fmt.Errorf("sts returned no credentials")
	}

	credential := &vault.Credential{
		Version:         1,
		AccessKeyId:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
	}
	if creds.Expiration != nil {
		credential.Expiration = creds.Expiration.UTC().Format(time.RFC3339)
	}
	return credential, nil
}
