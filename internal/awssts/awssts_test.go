package awssts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

var testExpiration = time.Date(2026, 11, 4, 1, 2, 3, 0, time.UTC)

func testCreds() *types.Credentials {
	return &types.Credentials{
		AccessKeyId:     aws.String("ASIATEST"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
		Expiration:      aws.Time(testExpiration),
	}
}

// fakeSTS records which operation was called and with what input.
type fakeSTS struct {
	called  string
	session *sts.GetSessionTokenInput
	fed     *sts.GetFederationTokenInput
	role    *sts.AssumeRoleInput
	err     error
	creds   *types.Credentials
}

func (f *fakeSTS) GetSessionToken(_ context.Context, in *sts.GetSessionTokenInput, _ ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error) {
	f.called, f.session = "GetSessionToken", in
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetSessionTokenOutput{Credentials: f.creds}, nil
}

func (f *fakeSTS) GetFederationToken(_ context.Context, in *sts.GetFederationTokenInput, _ ...func(*sts.Options)) (*sts.GetFederationTokenOutput, error) {
	f.called, f.fed = "GetFederationToken", in
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetFederationTokenOutput{Credentials: f.creds}, nil
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.called, f.role = "AssumeRole", in
	if f.err != nil {
		return nil, f.err
	}
	return &sts.AssumeRoleOutput{Credentials: f.creds}, nil
}

func TestGetCredentialsSessionToken(t *testing.T) {
	f := &fakeSTS{creds: testCreds()}
	c, err := GetCredentials(context.Background(), f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if f.called != "GetSessionToken" {
		t.Fatalf("called %s, want GetSessionToken", f.called)
	}
	if f.session.DurationSeconds != nil {
		t.Errorf("DurationSeconds = %d, want nil (STS default)", *f.session.DurationSeconds)
	}
	want := `{"Version":1,"AccessKeyId":"ASIATEST","SecretAccessKey":"secret","SessionToken":"token","Expiration":"2026-11-04T01:02:03Z"}`
	got, _ := json.Marshal(c)
	if string(got) != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}

func TestGetCredentialsSessionTokenDuration(t *testing.T) {
	f := &fakeSTS{creds: testCreds()}
	if _, err := GetCredentials(context.Background(), f, Options{Duration: 90 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if got := aws.ToInt32(f.session.DurationSeconds); got != 5400 {
		t.Errorf("DurationSeconds = %d, want 5400", got)
	}
}

func TestGetCredentialsFederationToken(t *testing.T) {
	f := &fakeSTS{creds: testCreds()}
	opts := Options{Duration: time.Hour, Policy: `{"Version":"2012-10-17"}`}
	if _, err := GetCredentials(context.Background(), f, opts); err != nil {
		t.Fatal(err)
	}
	if f.called != "GetFederationToken" {
		t.Fatalf("called %s, want GetFederationToken", f.called)
	}
	if aws.ToString(f.fed.Name) != SessionName {
		t.Errorf("Name = %q, want %q", aws.ToString(f.fed.Name), SessionName)
	}
	if aws.ToString(f.fed.Policy) != opts.Policy {
		t.Errorf("Policy = %q, want %q", aws.ToString(f.fed.Policy), opts.Policy)
	}
	if aws.ToInt32(f.fed.DurationSeconds) != 3600 {
		t.Errorf("DurationSeconds = %d, want 3600", aws.ToInt32(f.fed.DurationSeconds))
	}
}

func TestGetCredentialsAssumeRole(t *testing.T) {
	f := &fakeSTS{creds: testCreds()}
	opts := Options{RoleARN: "arn:aws:iam::123456789012:role/test", Policy: `{"Version":"2012-10-17"}`}
	if _, err := GetCredentials(context.Background(), f, opts); err != nil {
		t.Fatal(err)
	}
	if f.called != "AssumeRole" {
		t.Fatalf("called %s, want AssumeRole", f.called)
	}
	if aws.ToString(f.role.RoleArn) != opts.RoleARN {
		t.Errorf("RoleArn = %q", aws.ToString(f.role.RoleArn))
	}
	if aws.ToString(f.role.RoleSessionName) != SessionName {
		t.Errorf("RoleSessionName = %q", aws.ToString(f.role.RoleSessionName))
	}
	if aws.ToString(f.role.Policy) != opts.Policy {
		t.Errorf("Policy = %q", aws.ToString(f.role.Policy))
	}
	if f.role.DurationSeconds != nil {
		t.Errorf("DurationSeconds = %d, want nil", *f.role.DurationSeconds)
	}
}

func TestGetCredentialsAssumeRoleWithoutPolicy(t *testing.T) {
	f := &fakeSTS{creds: testCreds()}
	if _, err := GetCredentials(context.Background(), f, Options{RoleARN: "arn:aws:iam::123456789012:role/test"}); err != nil {
		t.Fatal(err)
	}
	if f.called != "AssumeRole" || f.role.Policy != nil {
		t.Errorf("called %s with Policy %v, want AssumeRole with nil Policy", f.called, f.role.Policy)
	}
}

func TestGetCredentialsError(t *testing.T) {
	f := &fakeSTS{err: errors.New("denied")}
	_, err := GetCredentials(context.Background(), f, Options{})
	if err == nil || !strings.Contains(err.Error(), "GetSessionToken") || !strings.Contains(err.Error(), "denied") {
		t.Errorf("err = %v, want wrapped GetSessionToken error", err)
	}
}

func TestGetCredentialsNoCredentials(t *testing.T) {
	f := &fakeSTS{}
	if _, err := GetCredentials(context.Background(), f, Options{}); err == nil {
		t.Error("expected an error when STS returns no credentials")
	}
}

func TestValidate(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/test"
	tests := []struct {
		opts    Options
		wantErr bool
	}{
		{Options{}, false},
		{Options{Duration: 15 * time.Minute}, false},
		{Options{Duration: 36 * time.Hour}, false},
		{Options{Duration: 14 * time.Minute}, true},
		{Options{Duration: 37 * time.Hour}, true},
		{Options{Duration: -time.Hour}, true},
		{Options{Duration: 25 * time.Minute}, false},
		{Options{Duration: time.Hour + 500*time.Millisecond}, true},
		{Options{RoleARN: role, Duration: 12 * time.Hour}, false},
		{Options{RoleARN: role, Duration: 13 * time.Hour}, true},
	}
	for _, tt := range tests {
		err := tt.opts.Validate()
		if (err != nil) != tt.wantErr {
			t.Errorf("Validate(%+v) err = %v, wantErr %v", tt.opts, err, tt.wantErr)
		}
	}
}

func TestReadPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	doc := "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"s3:ListAllMyBuckets\", \"Resource\": \"*\"}]\n}\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`
	if got != want {
		t.Errorf("ReadPolicy = %s, want %s", got, want)
	}
}

func TestReadPolicyInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicy(path); err == nil {
		t.Error("expected an error for invalid JSON")
	}
	if _, err := ReadPolicy(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	if r := Region(); r != "us-east-1" {
		t.Errorf("Region() = %s, want us-east-1", r)
	}
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1")
	if r := Region(); r != "eu-west-1" {
		t.Errorf("Region() = %s, want eu-west-1", r)
	}
	t.Setenv("AWS_REGION", "ap-south-1")
	if r := Region(); r != "ap-south-1" {
		t.Errorf("Region() = %s, want ap-south-1", r)
	}
}

// stubServer answers STS query-protocol requests and records the form
// values and Authorization header of the last request.
type stubServer struct {
	mu   sync.Mutex
	form url.Values
	auth string
}

func (s *stubServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.form, s.auth = r.PostForm, r.Header.Get("Authorization")
	s.mu.Unlock()

	action := r.PostForm.Get("Action")
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<%[1]sResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <%[1]sResult>
    <Credentials>
      <AccessKeyId>ASIA%[1]s</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>token</SessionToken>
      <Expiration>2026-11-04T01:02:03Z</Expiration>
    </Credentials>
  </%[1]sResult>
  <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>
</%[1]sResponse>`, action)
}

// TestClientAgainstStub drives the real SDK client against a local stub to
// check the request parameters on the wire and the parsed response.
func TestClientAgainstStub(t *testing.T) {
	stub := &stubServer{}
	srv := httptest.NewServer(stub)
	defer srv.Close()

	t.Setenv("AWS_REGION", "us-west-2")
	client := NewClient("AKIAVAULT", "vault-secret", func(o *sts.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
	})

	policy := `{"Version":"2012-10-17"}`
	tests := []struct {
		name   string
		opts   Options
		action string
		params map[string]string
	}{
		{"session", Options{Duration: time.Hour}, "GetSessionToken",
			map[string]string{"DurationSeconds": "3600"}},
		{"federation", Options{Policy: policy}, "GetFederationToken",
			map[string]string{"Name": SessionName, "Policy": policy}},
		{"role", Options{RoleARN: "arn:aws:iam::123456789012:role/test", Policy: policy, Duration: 2 * time.Hour}, "AssumeRole",
			map[string]string{"RoleArn": "arn:aws:iam::123456789012:role/test", "RoleSessionName": SessionName, "Policy": policy, "DurationSeconds": "7200"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := GetCredentials(context.Background(), client, tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			stub.mu.Lock()
			form, auth := stub.form, stub.auth
			stub.mu.Unlock()

			if got := form.Get("Action"); got != tt.action {
				t.Errorf("Action = %s, want %s", got, tt.action)
			}
			for k, v := range tt.params {
				if got := form.Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			if !strings.Contains(auth, "Credential=AKIAVAULT/") || !strings.Contains(auth, "/us-west-2/sts/") {
				t.Errorf("Authorization = %q, want it signed with the Vault key for us-west-2", auth)
			}
			if c.AccessKeyId != "ASIA"+tt.action || c.SessionToken != "token" || c.Expiration != "2026-11-04T01:02:03Z" {
				t.Errorf("credential = %+v", c)
			}
		})
	}
}
