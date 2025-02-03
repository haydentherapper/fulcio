// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package v1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
	"time"

	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/proto"
)

func failErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestReq(t *testing.T) {
	parent := "parent-ca"
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	failErr(t, err)

	uri := "sigstore.dev"
	parsedURI, err := url.Parse(uri)
	failErr(t, err)

	emailAddress := "foo@sigstore.dev"
	notAfter := time.Now().Add(time.Minute * 10)
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	failErr(t, err)
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{1, 2, 3}}

	cert := &x509.Certificate{
		NotAfter:        notAfter,
		EmailAddresses:  []string{emailAddress},
		URIs:            []*url.URL{parsedURI},
		ExtraExtensions: []pkix.Extension{ext},
	}

	expectedReq := &privatecapb.CreateCertificateRequest{
		Parent: parent,
		Certificate: &privatecapb.Certificate{
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    pubKeyBytes,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								DigitalSignature: true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								CodeSigning: true,
							},
						},
						AdditionalExtensions: []*privatecapb.X509Extension{
							{
								ObjectId: &privatecapb.ObjectId{
									ObjectIdPath: convertID(ext.Id),
								},
								Value: ext.Value,
							},
						},
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{},
						SubjectAltName: &privatecapb.SubjectAltNames{
							EmailAddresses: []string{emailAddress},
							Uris:           []string{uri},
						},
					},
				},
			},
		},
	}

	req, err := Req(parent, "", pubKeyBytes, cert)
	// We must copy over this field because we don't inject a clock, so
	// lifetime will always be different.
	expectedReq.Certificate.Lifetime = req.Certificate.Lifetime

	if err != nil {
		t.Fatalf("unexpected error, got: %v", err)
	}
	if !proto.Equal(req, expectedReq) {
		t.Fatalf("proto equality failed, expected: %v, got: %v", req, expectedReq)
	}
}

func TestReqCertAuthority(t *testing.T) {
	parent := "parent-ca"
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	failErr(t, err)

	uri := "sigstore.dev"
	parsedURI, err := url.Parse(uri)
	failErr(t, err)

	emailAddress := "foo@sigstore.dev"
	notAfter := time.Now().Add(time.Minute * 10)
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	failErr(t, err)
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3}, Value: []byte{1, 2, 3}}

	cert := &x509.Certificate{
		NotAfter:        notAfter,
		EmailAddresses:  []string{emailAddress},
		URIs:            []*url.URL{parsedURI},
		ExtraExtensions: []pkix.Extension{ext},
	}

	expectedReq := &privatecapb.CreateCertificateRequest{
		Parent:                        parent,
		IssuingCertificateAuthorityId: "cert-authority",
		Certificate: &privatecapb.Certificate{
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    pubKeyBytes,
					},
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								DigitalSignature: true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								CodeSigning: true,
							},
						},
						AdditionalExtensions: []*privatecapb.X509Extension{
							{
								ObjectId: &privatecapb.ObjectId{
									ObjectIdPath: convertID(ext.Id),
								},
								Value: ext.Value,
							},
						},
					},
					SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
						Subject: &privatecapb.Subject{},
						SubjectAltName: &privatecapb.SubjectAltNames{
							EmailAddresses: []string{emailAddress},
							Uris:           []string{uri},
						},
					},
				},
			},
		},
	}

	req, err := Req(parent, "cert-authority", pubKeyBytes, cert)
	// We must copy over this field because we don't inject a clock, so
	// lifetime will always be different.
	expectedReq.Certificate.Lifetime = req.Certificate.Lifetime

	if err != nil {
		t.Fatalf("unexpected error, got: %v", err)
	}
	if !proto.Equal(req, expectedReq) {
		t.Fatalf("proto equality failed, expected: %v, got: %v", req, expectedReq)
	}
}
