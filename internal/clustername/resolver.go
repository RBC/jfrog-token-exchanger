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

package clustername

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// ResolutionModeOIDCIssuer resolves an opaque, provider-agnostic identity from the
	// `iss` claim of the Kubernetes service account token. Every Kubernetes cluster with
	// a configured service-account-token issuer stamps that issuer into every SA token,
	// so this works the same way on any OIDC-compliant cluster.
	ResolutionModeOIDCIssuer = "oidc-issuer"
	// ServiceAccountTokenPath is the default path to the Kubernetes service account token
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: This is a file path, not a credential
)

// Resolver provides methods for resolving cluster names from the environment
type Resolver struct {
	// getEnv is a function to retrieve environment variables (allows testing)
	getEnv func(string) string
	// readFile is a function to read files (allows testing)
	readFile func(string) ([]byte, error)
}

// NewResolver creates a new cluster name resolver
func NewResolver() *Resolver {
	return &Resolver{
		getEnv:   os.Getenv,
		readFile: os.ReadFile,
	}
}

// ResolveClusterName resolves the cluster name based on the resolution mode
// Supported modes: "oidc-issuer"
func (r *Resolver) ResolveClusterName(mode string) (string, error) {
	switch mode {
	case ResolutionModeOIDCIssuer:
		return r.resolveOIDCIssuer()
	default:
		return "", fmt.Errorf("unsupported cluster name resolution mode: %s (supported modes: oidc-issuer)", mode)
	}
}

// resolveOIDCIssuer extracts the OIDC issuer (`iss` claim) from the Kubernetes service
// account token. The issuer URL is used verbatim as the opaque provider identity, since
// it is the actual trust anchor Artifactory validates the token's signature against in
// OIDC federation. This performs no cloud-specific parsing.
func (r *Resolver) resolveOIDCIssuer() (string, error) {
	tokenBytes, err := r.readFile(ServiceAccountTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %w", ServiceAccountTokenPath, err)
	}

	token := string(tokenBytes)
	if token == "" {
		return "", fmt.Errorf("service account token is empty")
	}

	issuer, err := extractIssuerFromToken(token)
	if err != nil {
		return "", fmt.Errorf("failed to extract issuer from token: %w", err)
	}

	return issuer, nil
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
