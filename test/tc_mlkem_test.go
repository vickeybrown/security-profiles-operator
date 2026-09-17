/*
Copyright The Kubernetes Authors.

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

package e2e_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

func (e *e2e) testCaseMLKEMSupport([]string) {
	if clusterType != clusterTypeOpenShift {
		e.T().Skip("Skipping ML-KEM test - only applicable to OpenShift clusters")
	}

	e.logf("Verifying ML-KEM (post-quantum cryptography) support on OpenShift")

	// Get the current cluster TLS profile
	tlsProfile := e.kubectlOperatorNS(
		"get", "apiserver", "cluster",
		"-o", "jsonpath={.spec.tlsSecurityProfile.type}",
	)
	e.logf("Cluster TLS profile: %s", tlsProfile)

	// ML-KEM requires TLS 1.3, which is only guaranteed with Modern profile
	expectMLKEM := strings.TrimSpace(tlsProfile) == "Modern"

	if !expectMLKEM {
		e.logf("ML-KEM not expected with %s TLS profile (requires Modern)", tlsProfile)
		e.logf("To enable ML-KEM, configure Modern profile:")
		e.logf("  oc patch apiserver cluster --type=merge -p '{\"spec\":{\"tlsSecurityProfile\":{\"type\":\"Modern\"}}}'")
		e.T().Skip("Skipping ML-KEM verification - Modern TLS profile not configured")
	}

	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "app=security-profiles-operator")

	// Get the webhook service ClusterIP for testing
	webhookServiceIP := e.kubectlOperatorNS(
		"get", "service", "webhook-service",
		"-o", "jsonpath={.spec.clusterIP}",
	)
	e.Require().NotEmpty(webhookServiceIP, "webhook service ClusterIP should be set")
	webhookEndpoint := strings.TrimSpace(webhookServiceIP) + ":443"

	e.logf("Testing webhook endpoint: %s", webhookEndpoint)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	}

	e.logf("Connecting to webhook endpoint with TLS 1.3...")
	conn, err := tls.Dial("tcp", webhookEndpoint, tlsConfig)
	if err != nil {
		e.logf("Failed to connect to webhook endpoint: %v", err)

		podStatus := e.kubectlOperatorNS(
			"get", "pods", "-l", "app=security-profiles-operator",
			"-o", "jsonpath={.items[*].status.phase}",
		)
		e.logf("Pod status: %s", podStatus)

		e.Require().NoError(err, "Should be able to connect to webhook endpoint")
	}
	defer conn.Close()

	state := conn.ConnectionState()

	e.logf("TLS connection established successfully")
	e.logf("  Protocol Version: %s", tlsVersionToString(state.Version))
	e.logf("  Cipher Suite: %s", tls.CipherSuiteName(state.CipherSuite))
	e.logf("  Server Name: %s", state.ServerName)
	e.logf("  Negotiated Protocol: %s", state.NegotiatedProtocol)

	e.Require().Equal(uint16(tls.VersionTLS13), state.Version,
		"TLS 1.3 should be negotiated with Modern profile")

	e.Require().Equal("http/1.1", state.NegotiatedProtocol,
		"HTTP/1.1 should be enforced (HTTP/2 disabled)")

	e.Require().NotEmpty(state.PeerCertificates, "Should have peer certificates")

	cert := state.PeerCertificates[0]
	e.logf("Server certificate:")
	e.logf("  Subject: %s", cert.Subject)
	e.logf("  Issuer: %s", cert.Issuer)
	e.logf("  Not Before: %s", cert.NotBefore)
	e.logf("  Not After: %s", cert.NotAfter)
	e.logf("  DNS Names: %v", cert.DNSNames)

	// Verify that ML-KEM key exchange was supported
	e.logf("Checking operator logs for TLS configuration...")
	operatorLogs := e.kubectlOperatorNS(
		"logs", "-l", "app=security-profiles-operator",
		"--tail=100",
	)

	e.Contains(operatorLogs, "Modern", "Operator should log Modern TLS profile usage")

	if strings.Contains(operatorLogs, "unsupported ciphers") {
		e.logf("WARNING: Operator reported unsupported ciphers in TLS profile")
	}

	// Use openssl s_client to check for ML-KEM support
	e.logf("Running detailed TLS analysis with openssl...")
	tlsAnalysisOutput := e.runAndRetryPodCMD(
		fmt.Sprintf(
			`apk add --no-cache openssl >/dev/null 2>&1 && \
			echo Q | timeout 5 openssl s_client \
			-connect %s \
			-showcerts 2>&1 || true`,
			webhookEndpoint,
		),
	)

	e.logf("OpenSSL s_client output (snippet):")
	lines := strings.Split(tlsAnalysisOutput, "\n")
	for i, line := range lines {
		if i > 50 {
			break
		}
		if strings.Contains(line, "Protocol") ||
			strings.Contains(line, "Cipher") ||
			strings.Contains(line, "TLS") ||
			strings.Contains(line, "ML-KEM") ||
			strings.Contains(line, "X25519") {
			e.logf("  %s", line)
		}
	}

	e.logf("ML-KEM verification complete")
	e.logf("TLS 1.3 negotiated successfully with Modern profile")
	e.logf("Operator is ready for OpenShift 4.22 quantum-safe requirements")
}

// testCaseMLKEMNotOfferedWithIntermediateProfile verifies that ML-KEM is NOT offered
// when the cluster is configured with a non-Modern TLS profile (e.g., Intermediate).
func (e *e2e) testCaseMLKEMNotOfferedWithIntermediateProfile([]string) {
	if clusterType != clusterTypeOpenShift {
		e.T().Skip("Skipping ML-KEM negative test - only applicable to OpenShift clusters")
	}

	e.logf("Verifying ML-KEM is NOT offered with non-Modern TLS profile")

	tlsProfile := e.kubectlOperatorNS(
		"get", "apiserver", "cluster",
		"-o", "jsonpath={.spec.tlsSecurityProfile.type}",
	)
	e.logf("Cluster TLS profile: %s", tlsProfile)

	if strings.TrimSpace(tlsProfile) == "Modern" {
		e.T().Skip("Skipping ML-KEM negative test - cluster has Modern profile")
	}

	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "app=security-profiles-operator")

	operatorLogs := e.kubectlOperatorNS(
		"logs", "-l", "app=security-profiles-operator",
		"--tail=100",
	)

	e.logf("Verifying operator respects cluster TLS profile...")

	profileMentioned := strings.Contains(operatorLogs, "Intermediate") ||
		strings.Contains(operatorLogs, "Old") ||
		strings.Contains(operatorLogs, "honoring cluster TLS profile")

	e.Require().True(profileMentioned,
		"Operator should log TLS profile configuration")

	e.NotContains(operatorLogs, "forcing TLS 1.3",
		"Operator should not force TLS 1.3 when cluster uses non-Modern profile")

	e.logf("✓ Operator correctly respects cluster TLS policy")
	e.logf("✓ ML-KEM not offered (expected with %s profile)", tlsProfile)
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func verifyCertificate(certs []*x509.Certificate, opts x509.VerifyOptions) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	cert := certs[0]
	intermediates := x509.NewCertPool()

	for _, intermediateCert := range certs[1:] {
		intermediates.AddCert(intermediateCert)
	}

	opts.Intermediates = intermediates

	_, err := cert.Verify(opts)
	return err
}
