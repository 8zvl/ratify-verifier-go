/*
Copyright The Ratify Authors.
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

package cosign

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify-go"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// certkey is the annotation key used to store the certificate in the artifact descriptor
const (
	certkey = "cosign.sigstore.dev/certificate"
)

// VerifierOptions contains configuration options for creating a new Verifier
type VerifierOptions struct {
	tmc root.TrustedMaterialCollection // Collection of trusted material for verification
}

// Verifier implements the signature verification logic for Cosign signatures
type Verifier struct {
	tmc root.TrustedMaterialCollection // Trusted material collection for verification
}

// NewVerifier creates a new instance of the Cosign verifier with the provided options
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	return &Verifier{
		tmc: opts.tmc,
	}, nil
}

// Name returns the name of the verifier
func (v *Verifier) Name() string {
	return "cosign"
}

// Type returns the type of the verifier
func (v *Verifier) Type() string {
	return "cosign"
}

// Verifiable checks if the given artifact descriptor can be verified by this verifier
// Currently returns false as implementation is pending
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return false
}

// Verify performs the signature verification process for the given artifact
// It handles the complete verification workflow including signature content extraction,
// verification content processing, and trusted material validation
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	sigContent, err := v.getSignatureContent(ctx, opts)
	if err != nil {
		return nil, err
	}
	verificationContent, err := v.getVerificationContent(ctx, opts)
	if err != nil {
		return nil, err
	}
	trustedMaterial, err := v.getTrustedMaterial(ctx, opts)
	if err != nil {
		return nil, err
	}
	digests, err := v.getArtifactDigests(ctx, opts)
	if err != nil {
		return nil, err
	}
	result := v.initResult(opts)
	// TODO: verify the signature with the artifact and implement desc to io.Reader function
	result.Err = verify.VerifySignatureWithArtifactDigests(sigContent, verificationContent, trustedMaterial, digests)
	return result, nil
}

// getSignatureContent extracts and processes the signature content from the artifact descriptor
func (v *Verifier) getSignatureContent(ctx context.Context, opts *ratify.VerifyOptions) (verify.SignatureContent, error) {
	desc := opts.ArtifactDescriptor
	digest, err := hex.DecodeString(desc.Digest.Hex())
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature blob digest: %w", err)
	}
	algorithm := desc.Digest.Algorithm().String()
	signatureContent := bundle.NewMessageSignature(digest, algorithm, desc.Data)
	return signatureContent, nil
}

// getVerificationContent extracts and processes the verification content (certificate) from the artifact descriptor
func (v *Verifier) getVerificationContent(ctx context.Context, opts *ratify.VerifyOptions) (verify.VerificationContent, error) {
	certPEM := opts.ArtifactDescriptor.Annotations[certkey]
	if certPEM == "" {
		return nil, nil
	}
	certs, err := cryptoutils.LoadCertificatesFromPEM(strings.NewReader(certPEM))
	if err != nil {
		return nil, err
	}
	return bundle.NewCertificate(certs[0]), nil
}

// getTrustedMaterial retrieves the trusted material needed for verification
func (v *Verifier) getTrustedMaterial(ctx context.Context, opts *ratify.VerifyOptions) (root.TrustedMaterial, error) {
	return v.getTrustedRoot(ctx)
}

// getArtifactDigests extracts and processes the artifact digests for verification
func (v *Verifier) getArtifactDigests(ctx context.Context, opts *ratify.VerifyOptions) ([]verify.ArtifactDigest, error) {
	desc := opts.ArtifactDescriptor
	digest, err := hex.DecodeString(desc.Digest.Hex())
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature blob digest: %w", err)
	}
	algorithm := desc.Digest.Algorithm().String()

	return []verify.ArtifactDigest{
		{
			Algorithm: algorithm,
			Digest:    digest,
		},
	}, nil
}

// initResult initializes a new verification result with basic information
func (v *Verifier) initResult(opts *ratify.VerifyOptions) *ratify.VerificationResult {
	return &ratify.VerificationResult{
		Verifier: v,
		Detail: map[string]string{
			"Artifact": opts.Repository + "@" + opts.SubjectDescriptor.Digest.String(),
		},
	}
}

// getTrustedRoot retrieves and initializes the trusted root from TUF
// This is used to establish the chain of trust for verification
func (v *Verifier) getTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	tufClient, err := tuf.NewFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing tuf: %w", err)
	}
	targetBytes, err := tufClient.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("error getting targets: %w", err)
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(targetBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating trusted root: %w", err)
	}

	return trustedRoot, nil
}
