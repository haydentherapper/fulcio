// Copyright 2022 The Sigstore Authors.
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

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	fulcioUrl    = "https://fulcio.sigstore.dev"
	oidcIssuer   = "https://oauth2.sigstore.dev/auth"
	oidcClientID = "sigstore"
)

func GetCert(priv crypto.PrivateKey, fc fulciopb.CAClient, oidcIssuer string, oidcClientID string) (*fulciopb.SigningCertificate, error) {
	tok, err := oauthflow.OIDConnect(oidcIssuer, oidcClientID, "", "", oauthflow.DefaultIDTokenGetter)
	if err != nil {
		return nil, err
	}

	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: tok.Subject}}
	derCSR, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		return nil, fmt.Errorf("error creating CSR: %w", err)
	}
	pemCSR := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: derCSR,
	})

	cscr := &fulciopb.CreateSigningCertificateRequest{
		OidcIdentityToken:         tok.RawString,
		CertificateSigningRequest: pemCSR,
	}
	return fc.CreateSigningCertificate(context.Background(), cscr)
}

func NewClient(fulcioURL string) (fulciopb.CAClient, error) {
	fulcioServer, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	dialOpt := grpc.WithTransportCredentials(insecure.NewCredentials())
	hostWithPort := fmt.Sprintf("%s:80", fulcioServer.Host)
	if fulcioServer.Scheme == "https" {
		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))
		hostWithPort = fmt.Sprintf("%s:443", fulcioServer.Host)
	}

	conn, err := grpc.Dial(hostWithPort, dialOpt)
	if err != nil {
		return nil, err
	}
	return fulciopb.NewCAClient(conn), nil
}

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	fClient, err := NewClient(fulcioUrl)
	if err != nil {
		log.Fatal(err)
	}

	certResp, err := GetCert(priv, fClient, oidcIssuer, oidcClientID)
	if err != nil {
		log.Fatal(err)
	}

	clientPEM, _ := pem.Decode([]byte(certResp.Certificates[0]))
	cert, err := x509.ParseCertificate(clientPEM.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Received signing cerificate with serial number: ", cert.SerialNumber)
}
