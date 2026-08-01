/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oidcissuer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// ServiceAccountTokenPath is the default path to the Kubernetes service account token.
	// Requires automountServiceAccountToken to stay enabled on this controller's own
	// ServiceAccount/pod: disabling it removes this file, which also breaks the manager's
	// own in-cluster k8s client bootstrap, not just issuer resolution.
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: This is a file path, not a credential
)

// Resolver resolves a provider identity from the environment
type Resolver struct {
	// getEnv is a function to retrieve environment variables (allows testing)
	getEnv func(string) string
	// readFile is a function to read files (allows testing)
	readFile func(string) ([]byte, error)
}

// NewResolver creates a new resolver
func NewResolver() *Resolver {
	return &Resolver{
		getEnv:   os.Getenv,
		readFile: os.ReadFile,
	}
}

// Resolve extracts the OIDC issuer (`iss` claim) from the Kubernetes service account
// token. The raw issuer is an arbitrary URL, not the alphanumeric-safe identifier
// Artifactory's OIDC provider name field expects, so Resolve also derives a stable
// providerName by hashing the canonicalized issuer with SHA-256. It returns the raw
// issuer alongside providerName so callers can log it: Artifactory must have a matching
// OIDC integration pre-configured with name=providerName and issuer_url=issuer.
func (r *Resolver) Resolve() (providerName string, issuer string, err error) {
	tokenBytes, err := r.readFile(ServiceAccountTokenPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read service account token from %s: %w", ServiceAccountTokenPath, err)
	}

	token := string(tokenBytes)
	if token == "" {
		return "", "", fmt.Errorf("service account token is empty")
	}

	issuer, err = extractIssuerFromToken(token)
	if err != nil {
		return "", "", fmt.Errorf("failed to extract issuer from token: %w", err)
	}

	return providerNameFromIssuer(issuer), issuer, nil
}

// providerNameFromIssuer derives a deterministic, Artifactory-safe provider name from an
// OIDC issuer URL by hex-encoding the SHA-256 digest of its canonicalized form, prefixed
// with "iss-". Artifactory provider names must start with a lowercase letter and contain
// only lowercase letters, digits and `-`; a bare hex digest can start with 0-9, which the
// prefix rules out. The trailing slash is stripped first: some issuers (e.g. AKS) include
// one and some (e.g. EKS) don't, and both forms identify the same trust anchor.
func providerNameFromIssuer(issuer string) string {
	canonical := strings.TrimSuffix(issuer, "/")
	sum := sha256.Sum256([]byte(canonical))
	return "iss-" + hex.EncodeToString(sum[:])
}

// extractIssuerFromToken decodes a JWT token and extracts the `iss` claim
func extractIssuerFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if claims.Iss == "" {
		return "", fmt.Errorf("iss claim is empty or missing")
	}

	return claims.Iss, nil
}
