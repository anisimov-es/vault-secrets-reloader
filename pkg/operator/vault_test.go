// Copyright © 2026 Contributors
// SPDX-License-Identifier: Apache-2.0
package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/bank-vaults/vault-secrets-reloader/api/v1alpha1"
	authentication "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func testOptions() Options {
	o := DefaultOptions()
	o.LeaderElection = false
	o.AllowHTTP = true
	o.AllowedAddresses = []string{"http://vault.test"}
	o.PollInterval = 100 * time.Millisecond
	o.RetryMin = 20 * time.Millisecond
	o.RetryMax = 100 * time.Millisecond
	o.RequestTimeout = 200 * time.Millisecond
	o.SyncTimeout = 200 * time.Millisecond
	o.AccessInterval = 100 * time.Millisecond
	o.VaultQPS = 1000
	return o
}
func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}
func TestMetadataOnlyAndPermissionRecovery(t *testing.T) {
	var deny atomic.Bool
	var version atomic.Int64
	version.Store(1)
	var forbiddenData atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/kubernetes/login":
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"test-token","lease_duration":600}}`)
		case "/v1/team/kv/metadata/payments/db":
			if deny.Load() {
				w.WriteHeader(403)
				_, _ = fmt.Fprint(w, `{"errors":["do not log synthetic password"]}`)
				return
			}
			n := version.Load()
			_, _ = fmt.Fprintf(w, `{"data":{"current_version":%d,"created_time":"key-created","custom_metadata":{"private":"never persist"},"versions":{"%d":{"created_time":"version-created","deletion_time":"","destroyed":false}}}}`, n, n)
		default:
			forbiddenData.Add(1)
			w.WriteHeader(403)
		}
	}))
	defer server.Close()
	o := testOptions()
	o.JWTFile = filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(o.JWTFile, []byte("synthetic-jwt"), 0600); err != nil {
		t.Fatal(err)
	}
	o.AllowedAddresses = []string{server.URL}
	reader := NewVaultReader(o, fake.NewClientset())
	defer reader.Close()
	s := Source{Tenant: "a", Address: server.URL, AuthSource: "controller", AuthMount: "kubernetes", Role: "a"}
	got, err := reader.Read(context.Background(), s, "team/kv/data/payments/db")
	if err != nil || got.Version != 1 {
		t.Fatalf("version=%v err=%v", got, err)
	}
	deny.Store(true)
	_, err = reader.Read(context.Background(), s, "team/kv/data/payments/db")
	if err == nil || err.Error() != "VaultAccessDenied" {
		t.Fatalf("expected sanitized access error, got %v", err)
	}
	deny.Store(false)
	version.Store(2)
	got, err = reader.Read(context.Background(), s, "team/kv/data/payments/db")
	if err != nil || got.Version != 2 {
		t.Fatalf("recovery=%v %v", got, err)
	}
	if forbiddenData.Load() != 0 {
		t.Fatal("attempted a non-metadata/data fallback endpoint")
	}
}
func TestMetadataValidationAndLifecycle(t *testing.T) {
	cases := []struct{ payload, code string }{
		{`{"data":{"current_version":0}}`, "InvalidMetadata"},
		{`{"data":{"current_version":1,"created_time":"k","versions":{"1":{"created_time":"v","destroyed":true}}}}`, "VersionDestroyed"},
		{`{"data":{"current_version":1,"created_time":"k","versions":{"1":{"created_time":"v","deletion_time":"2000-01-01T00:00:00Z"}}}}`, "VersionDeleted"},
		{`{"data":{"current_version":1,"created_time":"k","versions":{}}}`, "InvalidMetadata"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/login") {
					_, _ = fmt.Fprint(w, `{"auth":{"client_token":"t","lease_duration":600}}`)
				} else {
					_, _ = fmt.Fprint(w, tc.payload)
				}
			}))
			defer srv.Close()
			o := testOptions()
			o.JWTFile = filepath.Join(t.TempDir(), "jwt")
			_ = os.WriteFile(o.JWTFile, []byte("jwt"), 0600)
			o.AllowedAddresses = []string{srv.URL}
			v := NewVaultReader(o, fake.NewClientset())
			defer v.Close()
			_, err := v.Read(context.Background(), Source{Address: srv.URL, AuthMount: "kubernetes"}, "kv/data/x")
			if err == nil || err.Error() != tc.code {
				t.Fatalf("want %s, got %v", tc.code, err)
			}
		})
	}
}
func TestLoginFailureDoesNotBlockOtherIdentity(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role"] == "bad" {
				once.Do(func() { close(entered) })
				<-release
				w.WriteHeader(403)
				return
			}
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"good","lease_duration":600}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"current_version":1,"created_time":"k","versions":{"1":{"created_time":"v"}}}}`)
	}))
	defer srv.Close()
	defer close(release)
	o := testOptions()
	o.RequestTimeout = time.Second
	o.JWTFile = filepath.Join(t.TempDir(), "jwt")
	_ = os.WriteFile(o.JWTFile, []byte("jwt"), 0600)
	o.AllowedAddresses = []string{srv.URL}
	reader := NewVaultReader(o, fake.NewClientset())
	defer reader.Close()
	badDone := make(chan struct{})
	go func() {
		defer close(badDone)
		_, _ = reader.Read(context.Background(), Source{Tenant: "bad", Address: srv.URL, AuthMount: "kubernetes", Role: "bad"}, "kv/data/x")
	}()
	<-entered
	started := time.Now()
	_, err := reader.Read(context.Background(), Source{Tenant: "good", Address: srv.URL, AuthMount: "kubernetes", Role: "good"}, "kv/data/x")
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("other identity blocked behind failed login")
	}
	// close/release happens before session Close so the blocked login can finish.
	select {
	case <-badDone:
	case <-time.After(2 * time.Second):
		t.Fatal("login did not time out")
	}
}
func TestSourceSecurityAndPathParsing(t *testing.T) {
	w := testDeployment("team-a", "app")
	o := testOptions()
	w.Spec.Template.Annotations[prefix+"vault-addr"] = "http://vault.test"
	workload, _ := workloadOf(w)
	s, err := parseSource(workload, o)
	if err != nil {
		t.Fatal(err)
	}
	if s.Role != "default" || len(s.Paths) != 1 {
		t.Fatalf("unexpected source: %+v", s)
	}
	s2 := s
	s2.Tenant = "team-b"
	if s.ContextKey() == s2.ContextKey() {
		t.Fatal("cross-tenant credential contexts merged")
	}
	s2 = s
	s2.Role = "other"
	if s.ContextKey() == s2.ContextKey() {
		t.Fatal("roles merged")
	}
	w.Spec.Template.Annotations[prefix+"vault-addr"] = "http://attacker.test"
	workload, _ = workloadOf(w)
	if _, e := parseSource(workload, o); e == nil {
		t.Fatal("unapproved origin accepted")
	}
	w.Spec.Template.Annotations[prefix+"vault-addr"] = "http://vault.test"
	w.Spec.Template.Annotations[prefix+"vault-tls-secret"] = "any-secret"
	workload, _ = workloadOf(w)
	if _, e := parseSource(workload, o); e == nil {
		t.Fatal("unapproved Secret read")
	}
	for _, p := range []string{"kv/data/x", "team/kv/data/a b"} {
		got, e := metadataPath(p)
		if e != nil || !strings.Contains(got, "/metadata/") {
			t.Fatalf("path %s => %s %v", p, got, e)
		}
	}
	for _, p := range []string{"kv/x", "/kv/data/x", "kv/data/../x", "kv/data/x?x=y", "kv/data/x/data/y"} {
		if _, e := metadataPath(p); e == nil {
			t.Fatalf("unsafe/ambiguous path accepted: %s", p)
		}
	}
}
func TestDisabledSecretAndTokenRequestNeverReachAPI(t *testing.T) {
	k := fake.NewClientset(&core.Secret{ObjectMeta: meta.ObjectMeta{Name: "ca", Namespace: "a"}})
	o := testOptions()
	v := NewVaultReader(o, k)
	_, err := v.Read(context.Background(), Source{Tenant: "a", Address: "http://vault.test", CASecret: "ca"}, "kv/data/x")
	if err == nil {
		t.Fatal("unexpected success")
	}
	if len(k.Actions()) != 0 {
		t.Fatal("Secret API called despite disabled option")
	}
}

func TestWorkloadTokenRequestChecksApprovedUID(t *testing.T) {
	k := fake.NewClientset(&core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "payments", Namespace: "a", UID: "approved-uid"}})
	k.PrependReactor("create", "serviceaccounts", func(action ktesting.Action) (bool, runtime.Object, error) {
		if action.GetSubresource() != "token" {
			return false, nil, nil
		}
		request := action.(ktesting.CreateAction).GetObject().(*authentication.TokenRequest)
		if len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != "vault" {
			t.Error("unexpected audience")
		}
		return true, &authentication.TokenRequest{Status: authentication.TokenRequestStatus{Token: "workload-jwt"}}, nil
	})
	var loginJWT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			loginJWT = body["jwt"]
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"token","lease_duration":600}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"current_version":1,"created_time":"k","versions":{"1":{"created_time":"v"}}}}`)
	}))
	defer srv.Close()
	o := testOptions()
	o.AuthSource = "workload"
	o.AllowTokenRequest = true
	o.AllowedServiceAccounts = []string{"a/payments"}
	o.AllowedAddresses = []string{srv.URL}
	v := NewVaultReader(o, k)
	defer v.Close()
	s := Source{Tenant: "a", Address: srv.URL, AuthSource: "workload", AuthMount: "kubernetes", Role: "payments", ServiceAccount: "payments", ServiceAccountUID: "approved-uid", Audience: "vault"}
	if _, err := v.Read(context.Background(), s, "kv/data/x"); err != nil {
		t.Fatal(err)
	}
	if loginJWT != "workload-jwt" {
		t.Fatal("wrong identity used for Vault login")
	}
	s.ServiceAccount = "other"
	if _, err := v.Read(context.Background(), s, "kv/data/x"); err == nil || err.Error() != "ServiceAccountNotApproved" {
		t.Fatal("unapproved identity used")
	}
	s.ServiceAccount = "payments"
	s.ServiceAccountUID = "old-uid"
	if _, err := v.Read(context.Background(), s, "kv/data/x"); err == nil || err.Error() != "ServiceAccountIdentityChanged" {
		t.Fatal("stale identity used")
	}
}
func TestMetadataRecreateSameVersionChangesIdentity(t *testing.T) {
	a := api.Version{Version: 1, Created: "old", KeyCreated: "old-key"}
	b := api.Version{Version: 1, Created: "new", KeyCreated: "new-key"}
	if digest(a) == digest(b) {
		t.Fatal("metadata recreation not detected")
	}
}

func TestControllerJWTFileRotationInvalidatesLogin(t *testing.T) {
	var logins atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			logins.Add(1)
			_, _ = fmt.Fprint(w, `{"auth":{"client_token":"short-lived","lease_duration":600}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":{"current_version":1,"created_time":"k","versions":{"1":{"created_time":"v"}}}}`)
	}))
	defer srv.Close()
	o := testOptions()
	o.AllowedAddresses = []string{srv.URL}
	o.JWTFile = filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(o.JWTFile, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	v := NewVaultReader(o, fake.NewClientset())
	defer v.Close()
	s := Source{Tenant: "a", Address: srv.URL, AuthMount: "kubernetes", AuthSource: "controller"}
	if _, err := v.Read(context.Background(), s, "kv/data/x"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(context.Background(), s, "kv/data/x"); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 1 {
		t.Fatal("unexpected login before JWT rotation")
	}
	if err := os.WriteFile(o.JWTFile, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Read(context.Background(), s, "kv/data/x"); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 2 {
		t.Fatal("old login survived JWT file replacement")
	}
}

func TestReferenceCompatibilityWithoutReadingValues(t *testing.T) {
	o := testOptions()
	dep := testDeployment("a", "app")
	dep.Spec.Template.Spec.Containers[0].Env = []core.EnvVar{{Name: "ORDINARY", Value: "${HOME}/cache"}, {Name: "TEMPLATE_KEY", Value: "vault:kv/data/demo#${.password}"}, {Name: "PINNED", Value: "vault:kv/data/pinned#password#4"}}
	dep.Spec.Template.Spec.InitContainers = []core.Container{{Name: "init", Env: []core.EnvVar{{Name: "EXTRA", Value: "vault:kv/data/init#key"}}}}
	dep.Spec.Template.Annotations[prefix+"vault-from-path"] = "kv/data/all,kv/data/pinned#2"
	w, _ := workloadOf(dep)
	s, err := parseSource(w, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Paths) != 3 {
		t.Fatalf("expected env, init and from-path without pinned refs: %v", s.Paths)
	}
	dep.Spec.Template.Spec.Containers[0].Env = []core.EnvVar{{Name: "DYNAMIC", Value: "vault:kv/data/${name}#password"}}
	w, _ = workloadOf(dep)
	if _, err = parseSource(w, o); err == nil {
		t.Fatal("dynamic path accepted")
	}
}
