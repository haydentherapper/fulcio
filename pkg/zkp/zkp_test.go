// Copyright 2024 The Sigstore Authors.
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

package zkp

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestProver(t *testing.T) {
	g, h, err := NewGenerators()
	if err != nil {
		t.Fatal(err)
	}
	var ids []*big.Int
	var rs []*big.Int
	var commitments []CurvePoint
	for i := 0; i < 4; i++ {
		id := new(big.Int)
		id.SetInt64(int64(i))
		r := new(big.Int)
		var err error
		r, err = rand.Int(rand.Reader, elliptic.P256().Params().N)
		if err != nil {
			t.Fatal(err)
		}
		commit := PedersenCommitment(*g, *h, id, r)
		ids = append(ids, id)
		rs = append(rs, r)
		commitments = append(commitments, commit)
	}

	proof := SchnorrProve(commitments, *g, *h, 0, ids[0], rs[0])
	if err := SchnorrVerify(commitments, *g, *h, proof); err != nil {
		t.Fatal(err)
	}
}

func TestProviderWithFixedGenerators(t *testing.T) {
	g, h := NewFixedGenerators()

	var ids []*big.Int
	var rs []*big.Int
	var commitments []CurvePoint
	for i := 0; i < 4; i++ {
		id := new(big.Int)
		id.SetInt64(int64(i))
		r := new(big.Int)
		var err error
		r, err = rand.Int(rand.Reader, elliptic.P256().Params().N)
		if err != nil {
			t.Fatal(err)
		}
		commit := PedersenCommitment(*g, *h, id, r)
		ids = append(ids, id)
		rs = append(rs, r)
		commitments = append(commitments, commit)
	}

	proof := SchnorrProve(commitments, *g, *h, 0, ids[0], rs[0])
	if err := SchnorrVerify(commitments, *g, *h, proof); err != nil {
		t.Fatal(err)
	}
}

func TestProverWithOneCommitment(t *testing.T) {
	g, h, err := NewGenerators()
	if err != nil {
		t.Fatal(err)
	}

	id := new(big.Int)
	id.SetInt64(1)
	r := new(big.Int)
	r, err = rand.Int(rand.Reader, elliptic.P256().Params().N)
	if err != nil {
		t.Fatal(err)
	}
	commitment := PedersenCommitment(*g, *h, id, r)

	// test for a single commitment
	proof := SchnorrProve([]CurvePoint{commitment}, *g, *h, 0, id, r)
	if err := SchnorrVerify([]CurvePoint{commitment}, *g, *h, proof); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkCommitment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		g, h := NewFixedGenerators()
		id := new(big.Int)
		id.SetInt64(int64(1))
		r := new(big.Int)
		var err error
		r, err = rand.Int(rand.Reader, elliptic.P256().Params().N)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		_ = PedersenCommitment(*g, *h, id, r)
	}
}

func BenchmarkProve(b *testing.B) {
	// Benchmark prover for 1 to 100 commitmentes
	for s := 1; s <= 100; s++ {
		b.Run(fmt.Sprintf("SchnorrProve-%d", s), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()

				g, h := NewFixedGenerators()
				var ids []*big.Int
				var rs []*big.Int
				var commitments []CurvePoint
				// Generate commitments
				for j := 1; j <= s; j++ {
					id := new(big.Int)
					id.SetInt64(int64(j))
					r := new(big.Int)
					var err error
					r, err = rand.Int(rand.Reader, elliptic.P256().Params().N)
					if err != nil {
						b.Fatal(err)
					}
					commit := PedersenCommitment(*g, *h, id, r)
					ids = append(ids, id)
					rs = append(rs, r)
					commitments = append(commitments, commit)
				}
				index := 0

				b.StartTimer()
				_ = SchnorrProve(commitments, *g, *h, index, ids[index], rs[index])
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	// Benchmark verifier for 1 to 100 commitmentes
	for s := 1; s <= 100; s++ {
		b.Run(fmt.Sprintf("SchnorrVerify-%d", s), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()

				g, h := NewFixedGenerators()
				var ids []*big.Int
				var rs []*big.Int
				var commitments []CurvePoint
				// Generate commitments
				for j := 1; j <= s; j++ {
					id := new(big.Int)
					id.SetInt64(int64(j))
					r := new(big.Int)
					var err error
					r, err = rand.Int(rand.Reader, elliptic.P256().Params().N)
					if err != nil {
						b.Fatal(err)
					}
					commit := PedersenCommitment(*g, *h, id, r)
					ids = append(ids, id)
					rs = append(rs, r)
					commitments = append(commitments, commit)
				}
				index := 0
				// Run prover
				proof := SchnorrProve(commitments, *g, *h, index, ids[index], rs[index])

				b.StartTimer()
				if err := SchnorrVerify(commitments, *g, *h, proof); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
