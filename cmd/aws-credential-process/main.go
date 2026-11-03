package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Keeper-Security/aws-credential-process/internal/awssts"
	"github.com/Keeper-Security/aws-credential-process/internal/vault"
)

// stsTimeout bounds the STS request so the AWS CLI is never left waiting.
const stsTimeout = 30 * time.Second

func main() {
	/*
		This is the entry point for the AWS CLI Credential Process. It is
		invoked by the AWS CLI with the following config in ~/.aws/config:

		credential_process = path/to/keeper-aws-credential-process --uid <UID>

		The AWS CLI will call this executable with passed arguments. It
		credential process expects the UID of the credential to be fetched from
		the Vault, which is then marshalled into JSON, and returned to the AWS
		CLI via Stdout.

		With --sts, the Vault credential is exchanged for temporary STS
		credentials (see the awssts package for which STS call is used).

		Stdout is reserved for the credential JSON; errors go to Stderr, which
		the AWS CLI shows when the process fails.
	*/

	var (
		uid        string
		useSTS     bool
		roleARN    string
		policyPath string
		duration   time.Duration
	)

	flag.StringVar(&uid, "uid", "", "Credential UID")
	flag.BoolVar(&useSTS, "sts", false, "Exchange the Vault credential for temporary STS credentials")
	flag.StringVar(&roleARN, "role-arn", "", "With --sts, assume this role instead of creating a session token")
	flag.DurationVar(&duration, "duration", 0, "With --sts, lifetime of the temporary credentials, e.g. 1h or 90m (default: STS default)")
	flag.StringVar(&policyPath, "policy", "", "With --sts, path to a JSON policy document that limits the session's permissions")
	flag.Parse()

	if uid == "" {
		fail("UID is required")
	}

	// Returns non-flag arguments. This should be an empty slice.
	if len(flag.Args()) != 0 {
		fail("Unknown arguments provided")
	}

	durationSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "duration" {
			durationSet = true
		}
	})

	if !useSTS && (roleARN != "" || policyPath != "" || durationSet) {
		fail("--role-arn, --duration and --policy require --sts")
	}
	if durationSet && duration == 0 {
		fail(fmt.Sprintf("--duration must be at least %s", awssts.MinDuration))
	}

	// Validate the STS options before touching the Vault.
	opts := awssts.Options{RoleARN: roleARN, Duration: duration}
	if useSTS {
		if policyPath != "" {
			policy, err := awssts.ReadPolicy(policyPath)
			if err != nil {
				fail(err)
			}
			opts.Policy = policy
		}
		if err := opts.Validate(); err != nil {
			fail(err)
		}
	}

	// Fetch the credential from the Vault
	credential, err := vault.FetchCredential(uid)
	if err != nil {
		fail(err)
	}

	if useSTS {
		ctx, cancel := context.WithTimeout(context.Background(), stsTimeout)
		client := awssts.NewClient(credential.AccessKeyId, credential.SecretAccessKey)
		credential, err = awssts.GetCredentials(ctx, client, opts)
		cancel()
		if err != nil {
			fail(err)
		}
	}

	// Marshal the credential to JSON
	out, err := json.Marshal(credential)
	if err != nil {
		fail(err)
	}

	// Return the JSON to Stdout for the AWS CLI to consume
	fmt.Println(string(out))
	os.Exit(0)
}

// fail writes the error to Stderr and exits non-zero.
func fail(v any) {
	fmt.Fprintln(os.Stderr, v)
	os.Exit(1)
}
