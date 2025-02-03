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

package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/fulcio/pkg/ca/ephemeralca"
	"github.com/sigstore/fulcio/pkg/config"
	"github.com/sigstore/fulcio/pkg/generated/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDuplex(t *testing.T) {
	// Start a server with duplex on port 8089
	ctx := context.Background()
	ca, err := ephemeralca.NewEphemeralCA()
	if err != nil {
		t.Fatal(err)
	}
	port := 8089
	serverURL, err := url.Parse(fmt.Sprintf("http://localhost:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	metricsPort := 2114

	go func() {
		if err := StartDuplexServer(ctx, config.DefaultConfig, nil, ca, "localhost", port, metricsPort, nil); err != nil {
			log.Fatalf("error starting duplex server: %v", err)
		}
	}()

	// wait for duplex server to start up
	time.Sleep(time.Second * 5)

	var issuerUrls []string
	t.Run("http", func(t *testing.T) {
		// Make sure we can grab the configuration with the v2 endpoint
		client := api.NewClient(serverURL)
		resp, err := client.Configuration()
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Issuers) != 2 {
			t.Fatalf("didn't get expected number of issuers over HTTP: %v", resp.Issuers)
		}
		for _, i := range resp.Issuers {
			issuerUrls = append(issuerUrls, i.IssuerURL)
		}
	})

	var grpcIssuerUrls []string
	t.Run("grpc", func(t *testing.T) {
		// Grab the rootcert with the v2 endpoint
		conn, err := grpc.NewClient(fmt.Sprintf("localhost:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		grpcClient := protobuf.NewCAClient(conn)
		conf, err := grpcClient.GetConfiguration(ctx, &protobuf.GetConfigurationRequest{})
		if err != nil {
			t.Fatalf("error getting trust bundle: %v", err)
		}
		if len(conf.GetIssuers()) != 2 {
			t.Fatalf("didn't get expected number of issuesr over gRPC: %v", conf.GetIssuers())
		}
		for _, i := range conf.GetIssuers() {
			grpcIssuerUrls = append(grpcIssuerUrls, i.GetIssuerUrl())
		}
	})

	slices.Sort(issuerUrls)
	slices.Sort(grpcIssuerUrls)

	t.Run("compare issuers", func(t *testing.T) {
		if d := cmp.Diff(issuerUrls, grpcIssuerUrls); d != "" {
			t.Fatal(d)
		}
	})

	t.Run("prometheus", func(t *testing.T) {
		// make sure there are metrics on the metrics port
		url := fmt.Sprintf("http://localhost:%d/metrics", metricsPort)
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		// make sure there's something about hitting the GetConfiguration in there
		// this just confirms some metrics are being printed
		if !strings.Contains(string(contents), "GetConfiguration") {
			t.Fatalf("didn't get expected metrics output: %s", string(contents))
		}
	})
}
