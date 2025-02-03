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

package server

import (
	"context"
	"errors"
	"fmt"

	ctclient "github.com/google/certificate-transparency-go/client"
	health "google.golang.org/grpc/health/grpc_health_v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	certauth "github.com/sigstore/fulcio/pkg/ca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/ctl"
	fulciogrpc "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"github.com/sigstore/fulcio/pkg/identity"
	fulciorequest "github.com/sigstore/fulcio/pkg/request"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type GRPCCAServer interface {
	fulciogrpc.CAServer
	health.HealthServer
}

func NewGRPCCAServer(ct *ctclient.LogClient, ca certauth.CertificateAuthority, ip identity.IssuerPool) GRPCCAServer {
	return &grpcaCAServer{
		ct:         ct,
		ca:         ca,
		IssuerPool: ip,
	}
}

const (
	MetadataOIDCTokenKey        = "oidcidentitytoken"
	HTTPResponseCodeMetadataKey = "x-http-code"
	PEMCertificateChain         = "application/pem-certificate-chain"
)

type grpcaCAServer struct {
	fulciogrpc.UnimplementedCAServer
	ct *ctclient.LogClient
	ca certauth.CertificateAuthority
	identity.IssuerPool
}

func (g *grpcaCAServer) CreateSigningCertificate(ctx context.Context, request *fulciogrpc.CreateSigningCertificateRequest) (*fulciogrpc.SigningCertificate, error) {
	// OIDC token either is passed in gRPC field or was extracted from HTTP headers
	token := request.GetOidcIdentityToken()
	if token == "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			vals := md.Get(MetadataOIDCTokenKey)
			if len(vals) == 1 {
				token = vals[0]
			}
		}
	}

	// Authenticate OIDC ID token by checking signature
	principal, err := g.IssuerPool.Authenticate(ctx, token)
	if err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, invalidIdentityToken)
	}

	// Verify CSR, extract public key, and compare subjects
	csr, err := cryptoutils.ParseCSR(request.GetCertificateSigningRequest())
	if err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, invalidCSR)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, invalidSignature)
	}
	// Check for weak key parameters
	if err := cryptoutils.ValidatePubKey(csr.PublicKey); err != nil {
		return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, insecurePublicKey)
	}
	// TODO: Finish implementing
	ctx = fulciorequest.WithArtifactDigest(ctx, request.GetArtifactDigest())

	// TODO: Add Subject comparison for CSR, figure out which ext should contain identity and what identity

	result := &fulciogrpc.SigningCertificate{}

	// For CAs that do not support embedded SCTs or if the CT log is not configured
	if sctCa, ok := g.ca.(certauth.EmbeddedSCTCA); !ok || g.ct == nil {
		// currently configured CA doesn't support pre-certificate flow required to embed SCT in final certificate
		csc, err := g.ca.CreateCertificate(ctx, principal, csr.PublicKey)
		if err != nil {
			// if the error was due to invalid input in the request, return HTTP 400
			if _, ok := err.(certauth.ValidationError); ok {
				return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, err.Error())
			}
			err = fmt.Errorf("error creating certificate: %w", err)
			// otherwise return a 500 error to reflect that it is a transient server issue that the client can't resolve
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, genericCAError)
		}

		finalPEM, err := csc.CertPEM()
		if err != nil {
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalCert)
		}

		finalChainPEM, err := csc.ChainPEM()
		if err != nil {
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalCert)
		}

		result.Certificates = append([]string{finalPEM}, finalChainPEM...)
	} else {
		precert, err := sctCa.CreatePrecertificate(ctx, principal, csr.PublicKey)
		if err != nil {
			// if the error was due to invalid input in the request, return HTTP 400
			if _, ok := err.(certauth.ValidationError); ok {
				return nil, handleFulcioGRPCError(ctx, codes.InvalidArgument, err, err.Error())
			}
			err = fmt.Errorf("error creating a pre-certificate and chain: %w", err)
			// otherwise return a 500 error to reflect that it is a transient server issue that the client can't resolve
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, genericCAError)
		}
		// submit precertificate and chain to CT log
		sct, err := g.ct.AddPreChain(ctx, ctl.BuildCTChain(precert.PreCert, precert.CertChain))
		if err != nil {
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToEnterCertInCTL)
		}
		csc, err := sctCa.IssueFinalCertificate(ctx, precert, sct)
		if err != nil {
			err = fmt.Errorf("error issuing final certificate using the pre-certificate with CA backend: %w", err)
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, genericCAError)
		}

		finalPEM, err := csc.CertPEM()
		if err != nil {
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalCert)
		}
		finalChainPEM, err := csc.ChainPEM()
		if err != nil {
			return nil, handleFulcioGRPCError(ctx, codes.Internal, err, failedToMarshalCert)
		}

		result.Certificates = append([]string{finalPEM}, finalChainPEM...)
	}

	metricNewEntries.Inc()

	return result, nil
}

func (g *grpcaCAServer) GetConfiguration(ctx context.Context, _ *fulciogrpc.GetConfigurationRequest) (*fulciogrpc.Configuration, error) {
	cfg := config.FromContext(ctx)
	if cfg == nil {
		err := errors.New("configuration not loaded")
		return nil, handleFulcioGRPCError(ctx, codes.Internal, err, loadingFulcioConfigurationError)
	}

	return &fulciogrpc.Configuration{
		Issuers: cfg.ToIssuers(),
	}, nil
}

func (g *grpcaCAServer) Check(_ context.Context, _ *health.HealthCheckRequest) (*health.HealthCheckResponse, error) {
	return &health.HealthCheckResponse{Status: health.HealthCheckResponse_SERVING}, nil
}

func (g *grpcaCAServer) Watch(_ *health.HealthCheckRequest, _ health.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "unimplemented")
}
