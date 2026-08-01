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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOIDCIssuer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OIDCIssuer Suite")
}

// Helper function to create a mock JWT token with specified audiences and issuer
func createMockTokenWithIssuer(audiences interface{}, issuer string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"aud": audiences,
		"exp": 1234567890,
		"iss": issuer,
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("mock-signature"))

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

var _ = Describe("Resolver", func() {
	Context("Resolve", func() {
		It("should extract issuer from service account token (EKS-shaped)", func() {
			token := createMockTokenWithIssuer(
				[]interface{}{"https://kubernetes.default.svc"},
				"https://oidc.eks.eu-west-1.amazonaws.com/id/1234567890ABCDEF",
			)

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					if path == ServiceAccountTokenPath {
						return []byte(token), nil
					}
					return nil, fmt.Errorf("file not found")
				},
			}

			issuer, err := resolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(issuer).To(Equal("https://oidc.eks.eu-west-1.amazonaws.com/id/1234567890ABCDEF"))
		})

		It("should extract issuer from service account token (AKS-shaped)", func() {
			token := createMockTokenWithIssuer(
				[]interface{}{"https://mycompany.jfrog.io"},
				"https://eastus.oic.prod-aks.azure.com/tenant-id/cluster-id/",
			)

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(token), nil
				},
			}

			issuer, err := resolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(issuer).To(Equal("https://eastus.oic.prod-aks.azure.com/tenant-id/cluster-id/"))
		})

		It("should return error when token file cannot be read", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return nil, fmt.Errorf("permission denied")
				},
			}

			_, err := resolver.Resolve()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to read service account token"))
		})

		It("should return error when token is empty", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(""), nil
				},
			}

			_, err := resolver.Resolve()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("service account token is empty"))
		})

		It("should return error when iss claim is missing", func() {
			token := createMockTokenWithIssuer([]interface{}{"https://kubernetes.default.svc"}, "")

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(token), nil
				},
			}

			_, err := resolver.Resolve()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("iss claim is empty or missing"))
		})
	})

	Context("extractIssuerFromToken", func() {
		It("should return error for invalid JWT format", func() {
			_, err := extractIssuerFromToken("invalid-token")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid JWT format"))
		})

		It("should return error for invalid base64 encoding", func() {
			_, err := extractIssuerFromToken("header.invalid@base64.signature")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to decode JWT payload"))
		})

		It("should return error for invalid JSON in payload", func() {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{invalid json}`))
			signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))
			token := fmt.Sprintf("%s.%s.%s", header, payload, signature)

			_, err := extractIssuerFromToken(token)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to parse JWT claims"))
		})
	})

	Context("NewResolver", func() {
		It("should create a resolver with os.Getenv and os.ReadFile", func() {
			resolver := NewResolver()
			Expect(resolver).NotTo(BeNil())
			Expect(resolver.getEnv).NotTo(BeNil())
			Expect(resolver.readFile).NotTo(BeNil())
		})
	})
})
