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
	// ResolutionModeAzure is the cluster name resolution mode for Azure Kubernetes Service.
	// Deprecated: use ResolutionModeOIDCIssuer instead, which works identically on any
	// OIDC-compliant cluster (AKS, EKS, etc.) with no cloud-specific parsing.
	ResolutionModeAzure = "azure"
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
// Supported modes: "azure" (deprecated), "oidc-issuer"
func (r *Resolver) ResolveClusterName(mode string) (string, error) {
	switch mode {
	case ResolutionModeAzure:
		return r.resolveAzureClusterName()
	case ResolutionModeOIDCIssuer:
		return r.resolveOIDCIssuer()
	default:
		return "", fmt.Errorf("unsupported cluster name resolution mode: %s (supported modes: azure, oidc-issuer)", mode)
	}
}

// resolveOIDCIssuer extracts the OIDC issuer (`iss` claim) from the Kubernetes service
// account token. Unlike resolveAzureClusterName, this performs no cloud-specific parsing:
// the issuer URL is used verbatim as the opaque provider identity, since it is the actual
// trust anchor Artifactory validates the token's signature against in OIDC federation.
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

// resolveAzureClusterName extracts the cluster name from the Kubernetes service account token
// It reads the token from /var/run/secrets/kubernetes.io/serviceaccount/token,
// decodes the JWT, and extracts the cluster name from the audience claim.
// Expected audience format: https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io
// Returns: cluster-name
func (r *Resolver) resolveAzureClusterName() (string, error) {
	// Read the service account token
	tokenBytes, err := r.readFile(ServiceAccountTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %w", ServiceAccountTokenPath, err)
	}

	token := string(tokenBytes)
	if token == "" {
		return "", fmt.Errorf("service account token is empty")
	}

	// Decode JWT without verification (we only need to read the payload)
	clusterName, err := extractClusterNameFromToken(token)
	if err != nil {
		return "", fmt.Errorf("failed to extract cluster name from token: %w", err)
	}

	return clusterName, nil
}

// extractClusterNameFromToken decodes a JWT token and extracts the cluster name from the audience claim
func extractClusterNameFromToken(token string) (string, error) {
	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the JSON payload
	var claims struct {
		Aud interface{} `json:"aud"` // Can be string or []string
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Extract audiences (handle both string and array formats)
	var audiences []string
	switch aud := claims.Aud.(type) {
	case string:
		audiences = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				audiences = append(audiences, s)
			}
		}
	default:
		return "", fmt.Errorf("unexpected aud claim type: %T", claims.Aud)
	}

	// Find the AKS audience and extract cluster name
	for _, aud := range audiences {
		clusterName, err := extractClusterNameFromAudience(aud)
		if err == nil {
			return clusterName, nil
		}
	}

	return "", fmt.Errorf("no valid AKS audience found in token (expected format: https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io)")
}

// extractClusterNameFromAudience extracts the cluster name from an AKS audience URL
// Expected format: https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io
// Returns error if format doesn't match
func extractClusterNameFromAudience(audience string) (string, error) {
	// Check if this looks like an AKS audience URL
	if !strings.HasPrefix(audience, "https://") {
		return "", fmt.Errorf("audience does not start with https://: %s", audience)
	}
	if !strings.Contains(audience, ".hcp.") {
		return "", fmt.Errorf("audience does not contain .hcp.: %s", audience)
	}
	if !strings.Contains(audience, ".azmk8s.io") {
		return "", fmt.Errorf("audience does not contain .azmk8s.io: %s", audience)
	}

	// Remove the https:// prefix
	host := strings.TrimPrefix(audience, "https://")

	// Extract cluster name (everything before -dns)
	dnsIndex := strings.Index(host, "-dns-")
	if dnsIndex == -1 {
		return "", fmt.Errorf("audience does not contain -dns- segment: %s", audience)
	}

	clusterName := host[:dnsIndex]
	if clusterName == "" {
		return "", fmt.Errorf("cluster name is empty in audience: %s", audience)
	}

	return clusterName, nil
}
