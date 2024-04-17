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
	"crypto/sha256"
	"fmt"
	"math/big"

	"filippo.io/nistec"
)

type CurvePoint struct {
	X, Y *big.Int
}

func NewGenerators() (*CurvePoint, *CurvePoint, error) {
	curve := elliptic.P256()
	groupOrder := curve.Params().N
	var G, H CurvePoint

	// pick base point as first fixed generator
	G.X = curve.Params().Gx
	G.Y = curve.Params().Gy

	// pick random value from [0, order)
	k, err := rand.Int(rand.Reader, groupOrder)
	if err != nil {
		return nil, nil, err
	}
	// second fixed generator
	H.X, H.Y = curve.ScalarBaseMult(k.Bytes())

	return &G, &H, nil
}

// Output persisted from one run of NewGenerators():
// G.X.String() = 48439561293906451759052585252797914202762949526041747995844080717082404635286
// G.Y.String() = 36134250956749795798585127919587881956611106672985015071877198253568414405109
// H.X.String() = 83431607445495283463740962512595338344954605535626826964890388736599494407491
// H.Y.String() = 53978890700359539857313910375500508685329409963827464688231041668047831465584
func NewFixedGenerators() (*CurvePoint, *CurvePoint) {
	gx := new(big.Int)
	gx.SetString("48439561293906451759052585252797914202762949526041747995844080717082404635286", 10)
	gy := new(big.Int)
	gy.SetString("36134250956749795798585127919587881956611106672985015071877198253568414405109", 10)
	hx := new(big.Int)
	hx.SetString("83431607445495283463740962512595338344954605535626826964890388736599494407491", 10)
	hy := new(big.Int)
	hy.SetString("53978890700359539857313910375500508685329409963827464688231041668047831465584", 10)

	var g, h CurvePoint
	g.X, g.Y = gx, gy
	h.X, h.Y = hx, hy

	return &g, &h
}

// Computes Commit(id;r)=(g^id)(h^r)
func PedersenCommitment(G, H CurvePoint, id, r *big.Int) CurvePoint {
	curve := elliptic.P256()
	g1, g2 := curve.ScalarMult(G.X, G.Y, id.Bytes()) // g^id
	h1, h2 := curve.ScalarMult(H.X, H.Y, r.Bytes())  // h^r
	var C CurvePoint
	C.X, C.Y = curve.Add(g1, g2, h1, h2) // g^id * h^r
	return C
}

func (c CurvePoint) Equals(other CurvePoint) bool {
	return c.X.Cmp(other.X) == 0 && c.Y.Cmp(other.Y) == 0
}

type IndexProof struct {
	Y_j             CurvePoint
	E_j, Z_j0, Z_j1 *big.Int
}

type SchnorrProof struct {
	Proof []IndexProof
}

func SchnorrProve(L []CurvePoint, G, H CurvePoint, i int, id, r *big.Int) SchnorrProof {
	curve := elliptic.P256()
	groupOrder := curve.Params().N

	var proof SchnorrProof
	proof.Proof = make([]IndexProof, len(L)) // {y_j, e_j, z_j0, z_j1} for [0, len(L))

	for j, L_j := range L {
		if j != i { // run simulator
			// ej, zj0, zj1 <-- Fp
			e_j := SampleFromField(curve)
			z_j_0 := SampleFromField(curve)
			z_j_1 := SampleFromField(curve)
			// Compute yj = (g^zj0)(h^zj1) / L[i]^ej
			g1, g2 := curve.ScalarMult(G.X, G.Y, z_j_0.Bytes())   // g^zj0
			h1, h2 := curve.ScalarMult(H.X, H.Y, z_j_1.Bytes())   // h^zj1
			l1, l2 := curve.ScalarMult(L_j.X, L_j.Y, e_j.Bytes()) // L[i]^ej
			var temp, y_j CurvePoint
			temp.X, temp.Y = curve.Add(g1, g2, h1, h2)

			// y_j.X, y_j.Y = curve.Add(temp.X, temp.Y, l1, l2.Neg(l2)) // (x,y) inverse = (x, -y)
			// Hack to get around curve.Add not working for point inverse
			b := elliptic.Marshal(curve, temp.X, temp.Y)
			p1, err := nistec.NewP256Point().SetBytes(b)
			if err != nil {
				panic(err)
			}
			b = elliptic.Marshal(curve, l1, l2)
			p2, err := nistec.NewP256Point().SetBytes(b)
			if err != nil {
				panic(err)
			}
			p2 = p2.Negate(p2)
			p1 = p1.Add(p1, p2)
			y_j.X, y_j.Y = elliptic.Unmarshal(curve, p1.Bytes())

			proof.Proof[j] = IndexProof{y_j, e_j, z_j_0, z_j_1}
		}
	}
	// run prover
	s := SampleFromField(curve)
	t := SampleFromField(curve)

	g1, g2 := curve.ScalarMult(G.X, G.Y, s.Bytes()) // g^s
	h1, h2 := curve.ScalarMult(H.X, H.Y, t.Bytes()) // h^t
	var y_i CurvePoint
	y_i.X, y_i.Y = curve.Add(g1, g2, h1, h2) // g^s * h^t
	// init proof at index i for hash computation
	proof.Proof[i] = IndexProof{y_i, nil, nil, nil}

	e_i := new(big.Int)
	z_i_0 := new(big.Int)
	z_i_1 := new(big.Int)

	// ei = H(y1..yn) ^ (e1^e2^..e^n where j != i)
	var e_xor *big.Int
	h := sha256.New()
	for j, p := range proof.Proof {
		h.Write(p.Y_j.X.Bytes())
		h.Write([]byte{','})
		h.Write(p.Y_j.Y.Bytes())
		h.Write([]byte{','})

		if j != i {
			if e_xor == nil {
				e_xor = new(big.Int)
				e_xor.Set(p.E_j)
			} else {
				e_xor.Xor(e_xor, p.E_j)
			}
		}
	}
	e_i.SetBytes(h.Sum([]byte{}))
	if e_xor != nil {
		e_i.Xor(e_i, e_xor)
	}

	// z_j0 = s + ei * id (mod N)
	temp := new(big.Int)
	temp.Mul(e_i, id)
	z_i_0.Set(s)
	z_i_0.Add(z_i_0, temp)
	z_i_0.Mod(z_i_0, groupOrder)

	// z_j1 = t + ei * r (mod N)
	temp = new(big.Int)
	temp.Mul(e_i, r)
	z_i_1.Set(t)
	z_i_1.Add(z_i_1, temp)
	z_i_1.Mod(z_i_1, groupOrder)

	proof.Proof[i] = IndexProof{y_i, e_i, z_i_0, z_i_1}
	return proof
}

func SchnorrVerify(L []CurvePoint, G, H CurvePoint, proof SchnorrProof) error {
	curve := elliptic.P256()

	// h = H(y1..yn)
	// e_xor = (e1..e^n)
	var e_xor *big.Int
	h := sha256.New()
	for i, p := range proof.Proof {
		h.Write(p.Y_j.X.Bytes())
		h.Write([]byte{','})
		h.Write(p.Y_j.Y.Bytes())
		h.Write([]byte{','})

		if i == 0 {
			e_xor = new(big.Int)
			e_xor.Set(p.E_j)
		} else {
			e_xor.Xor(e_xor, p.E_j)
		}
	}
	hash := new(big.Int)
	hash.SetBytes(h.Sum([]byte{}))
	if hash.Cmp(e_xor) != 0 {
		return fmt.Errorf("hash and e_xor not equal")
	}
	// for all commitments, err out if proof does not verify
	for j, L_j := range L {
		p := proof.Proof[j]
		l1, l2 := curve.ScalarMult(L_j.X, L_j.Y, p.E_j.Bytes()) // L[j]^ej
		l1, l2 = curve.Add(p.Y_j.X, p.Y_j.Y, l1, l2)            // yj * L[j]^ej
		g1, g2 := curve.ScalarMult(G.X, G.Y, p.Z_j0.Bytes())    // g^zj0
		h1, h2 := curve.ScalarMult(H.X, H.Y, p.Z_j1.Bytes())    // h^zj1
		var curveAdd CurvePoint
		curveAdd.X, curveAdd.Y = curve.Add(g1, g2, h1, h2)
		if curveAdd.X.Cmp(l1) != 0 || curveAdd.Y.Cmp(l2) != 0 {
			return fmt.Errorf("yj not equal")
		}
	}
	return nil
}

func SampleFromField(curve elliptic.Curve) *big.Int {
	groupOrder := curve.Params().N
	r, err := rand.Int(rand.Reader, groupOrder)
	if err != nil {
		panic(err)
	}
	return r
}
