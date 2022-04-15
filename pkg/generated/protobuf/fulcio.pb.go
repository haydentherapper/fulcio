//
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.12.4
// source: fulcio.proto

package protobuf

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type PublicKeyAlgorithm int32

const (
	PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_UNSPECIFIED PublicKeyAlgorithm = 0
	PublicKeyAlgorithm_RSA_PSS                          PublicKeyAlgorithm = 1
	PublicKeyAlgorithm_ECDSA                            PublicKeyAlgorithm = 2
	PublicKeyAlgorithm_ED25519                          PublicKeyAlgorithm = 3
)

// Enum value maps for PublicKeyAlgorithm.
var (
	PublicKeyAlgorithm_name = map[int32]string{
		0: "PUBLIC_KEY_ALGORITHM_UNSPECIFIED",
		1: "RSA_PSS",
		2: "ECDSA",
		3: "ED25519",
	}
	PublicKeyAlgorithm_value = map[string]int32{
		"PUBLIC_KEY_ALGORITHM_UNSPECIFIED": 0,
		"RSA_PSS":                          1,
		"ECDSA":                            2,
		"ED25519":                          3,
	}
)

func (x PublicKeyAlgorithm) Enum() *PublicKeyAlgorithm {
	p := new(PublicKeyAlgorithm)
	*p = x
	return p
}

func (x PublicKeyAlgorithm) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PublicKeyAlgorithm) Descriptor() protoreflect.EnumDescriptor {
	return file_fulcio_proto_enumTypes[0].Descriptor()
}

func (PublicKeyAlgorithm) Type() protoreflect.EnumType {
	return &file_fulcio_proto_enumTypes[0]
}

func (x PublicKeyAlgorithm) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PublicKeyAlgorithm.Descriptor instead.
func (PublicKeyAlgorithm) EnumDescriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{0}
}

type CreateSigningCertificateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// Identity information about who possesses the private / public key pair presented
	Credentials *Credentials `protobuf:"bytes,1,opt,name=credentials,proto3" json:"credentials,omitempty"`
	//
	// The public key to be stored in the requested certificate
	PublicKey *PublicKey `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	//
	// Proof that the client possesses the private key; must be verifiable by provided public key
	//
	// This is a currently a signature over the `sub` claim from the OIDC identity token
	ProofOfPossession []byte `protobuf:"bytes,3,opt,name=proof_of_possession,json=proofOfPossession,proto3" json:"proof_of_possession,omitempty"`
}

func (x *CreateSigningCertificateRequest) Reset() {
	*x = CreateSigningCertificateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateSigningCertificateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateSigningCertificateRequest) ProtoMessage() {}

func (x *CreateSigningCertificateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateSigningCertificateRequest.ProtoReflect.Descriptor instead.
func (*CreateSigningCertificateRequest) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{0}
}

func (x *CreateSigningCertificateRequest) GetCredentials() *Credentials {
	if x != nil {
		return x.Credentials
	}
	return nil
}

func (x *CreateSigningCertificateRequest) GetPublicKey() *PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *CreateSigningCertificateRequest) GetProofOfPossession() []byte {
	if x != nil {
		return x.ProofOfPossession
	}
	return nil
}

type Credentials struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Credentials:
	//	*Credentials_OidcIdentityToken
	Credentials isCredentials_Credentials `protobuf_oneof:"credentials"`
}

func (x *Credentials) Reset() {
	*x = Credentials{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Credentials) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Credentials) ProtoMessage() {}

func (x *Credentials) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Credentials.ProtoReflect.Descriptor instead.
func (*Credentials) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{1}
}

func (m *Credentials) GetCredentials() isCredentials_Credentials {
	if m != nil {
		return m.Credentials
	}
	return nil
}

func (x *Credentials) GetOidcIdentityToken() string {
	if x, ok := x.GetCredentials().(*Credentials_OidcIdentityToken); ok {
		return x.OidcIdentityToken
	}
	return ""
}

type isCredentials_Credentials interface {
	isCredentials_Credentials()
}

type Credentials_OidcIdentityToken struct {
	//
	// The OIDC token that identifies the caller
	OidcIdentityToken string `protobuf:"bytes,1,opt,name=oidc_identity_token,json=oidcIdentityToken,proto3,oneof"`
}

func (*Credentials_OidcIdentityToken) isCredentials_Credentials() {}

type PublicKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The cryptographic algorithm to use with the key material
	Algorithm PublicKeyAlgorithm `protobuf:"varint,1,opt,name=algorithm,proto3,enum=dev.sigstore.fulcio.v2.PublicKeyAlgorithm" json:"algorithm,omitempty"`
	//
	// PEM encoded public key
	Content string `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"`
}

func (x *PublicKey) Reset() {
	*x = PublicKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicKey) ProtoMessage() {}

func (x *PublicKey) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicKey.ProtoReflect.Descriptor instead.
func (*PublicKey) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{2}
}

func (x *PublicKey) GetAlgorithm() PublicKeyAlgorithm {
	if x != nil {
		return x.Algorithm
	}
	return PublicKeyAlgorithm_PUBLIC_KEY_ALGORITHM_UNSPECIFIED
}

func (x *PublicKey) GetContent() string {
	if x != nil {
		return x.Content
	}
	return ""
}

type SigningCertificate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Certificate:
	//	*SigningCertificate_SignedCertificateDetachedSct
	//	*SigningCertificate_SignedCertificateEmbeddedSct
	Certificate isSigningCertificate_Certificate `protobuf_oneof:"certificate"`
}

func (x *SigningCertificate) Reset() {
	*x = SigningCertificate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SigningCertificate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningCertificate) ProtoMessage() {}

func (x *SigningCertificate) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningCertificate.ProtoReflect.Descriptor instead.
func (*SigningCertificate) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{3}
}

func (m *SigningCertificate) GetCertificate() isSigningCertificate_Certificate {
	if m != nil {
		return m.Certificate
	}
	return nil
}

func (x *SigningCertificate) GetSignedCertificateDetachedSct() *SigningCertificateDetachedSCT {
	if x, ok := x.GetCertificate().(*SigningCertificate_SignedCertificateDetachedSct); ok {
		return x.SignedCertificateDetachedSct
	}
	return nil
}

func (x *SigningCertificate) GetSignedCertificateEmbeddedSct() *SigningCertificateEmbeddedSCT {
	if x, ok := x.GetCertificate().(*SigningCertificate_SignedCertificateEmbeddedSct); ok {
		return x.SignedCertificateEmbeddedSct
	}
	return nil
}

type isSigningCertificate_Certificate interface {
	isSigningCertificate_Certificate()
}

type SigningCertificate_SignedCertificateDetachedSct struct {
	SignedCertificateDetachedSct *SigningCertificateDetachedSCT `protobuf:"bytes,1,opt,name=signed_certificate_detached_sct,json=signedCertificateDetachedSct,proto3,oneof"`
}

type SigningCertificate_SignedCertificateEmbeddedSct struct {
	SignedCertificateEmbeddedSct *SigningCertificateEmbeddedSCT `protobuf:"bytes,2,opt,name=signed_certificate_embedded_sct,json=signedCertificateEmbeddedSct,proto3,oneof"`
}

func (*SigningCertificate_SignedCertificateDetachedSct) isSigningCertificate_Certificate() {}

func (*SigningCertificate_SignedCertificateEmbeddedSct) isSigningCertificate_Certificate() {}

// (-- api-linter: core::0142::time-field-type=disabled
//     aip.dev/not-precedent: SCT is defined in RFC6962 and we keep the name consistent for easier understanding. --)
type SigningCertificateDetachedSCT struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The certificate chain serialized with the leaf certificate first, followed
	// by all intermediate certificates (if present), finishing with the root certificate.
	//
	// All values are PEM-encoded certificates.
	Chain *CertificateChain `protobuf:"bytes,1,opt,name=chain,proto3" json:"chain,omitempty"`
	//
	// The signed certificate timestamp is a promise for including the certificate in
	// a certificate transparency log. It can be "stapled" to verify the inclusion of
	// a certificate in the log in an offline fashion.
	SignedCertificateTimestamp []byte `protobuf:"bytes,2,opt,name=signed_certificate_timestamp,json=signedCertificateTimestamp,proto3" json:"signed_certificate_timestamp,omitempty"`
}

func (x *SigningCertificateDetachedSCT) Reset() {
	*x = SigningCertificateDetachedSCT{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SigningCertificateDetachedSCT) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningCertificateDetachedSCT) ProtoMessage() {}

func (x *SigningCertificateDetachedSCT) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningCertificateDetachedSCT.ProtoReflect.Descriptor instead.
func (*SigningCertificateDetachedSCT) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{4}
}

func (x *SigningCertificateDetachedSCT) GetChain() *CertificateChain {
	if x != nil {
		return x.Chain
	}
	return nil
}

func (x *SigningCertificateDetachedSCT) GetSignedCertificateTimestamp() []byte {
	if x != nil {
		return x.SignedCertificateTimestamp
	}
	return nil
}

type SigningCertificateEmbeddedSCT struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The certificate chain serialized with the leaf certificate first, followed
	// by all intermediate certificates (if present), finishing with the root certificate.
	//
	// All values are PEM-encoded certificates.
	Chain *CertificateChain `protobuf:"bytes,1,opt,name=chain,proto3" json:"chain,omitempty"`
}

func (x *SigningCertificateEmbeddedSCT) Reset() {
	*x = SigningCertificateEmbeddedSCT{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SigningCertificateEmbeddedSCT) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SigningCertificateEmbeddedSCT) ProtoMessage() {}

func (x *SigningCertificateEmbeddedSCT) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SigningCertificateEmbeddedSCT.ProtoReflect.Descriptor instead.
func (*SigningCertificateEmbeddedSCT) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{5}
}

func (x *SigningCertificateEmbeddedSCT) GetChain() *CertificateChain {
	if x != nil {
		return x.Chain
	}
	return nil
}

// This is created for forward compatibility in case we want to add fields to the TrustBundle service in the future
type GetTrustBundleRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetTrustBundleRequest) Reset() {
	*x = GetTrustBundleRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetTrustBundleRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetTrustBundleRequest) ProtoMessage() {}

func (x *GetTrustBundleRequest) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetTrustBundleRequest.ProtoReflect.Descriptor instead.
func (*GetTrustBundleRequest) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{6}
}

type TrustBundle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The set of PEM-encoded certificate chains for this Fulcio instance; each chain will start with any
	// intermediate certificates (if present), finishing with the root certificate.
	Chains []*CertificateChain `protobuf:"bytes,1,rep,name=chains,proto3" json:"chains,omitempty"`
}

func (x *TrustBundle) Reset() {
	*x = TrustBundle{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TrustBundle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TrustBundle) ProtoMessage() {}

func (x *TrustBundle) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TrustBundle.ProtoReflect.Descriptor instead.
func (*TrustBundle) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{7}
}

func (x *TrustBundle) GetChains() []*CertificateChain {
	if x != nil {
		return x.Chains
	}
	return nil
}

type CertificateChain struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	// The PEM-encoded certificate chain, ordered from leaf to intermediate to root as applicable.
	Certificates []string `protobuf:"bytes,1,rep,name=certificates,proto3" json:"certificates,omitempty"`
}

func (x *CertificateChain) Reset() {
	*x = CertificateChain{}
	if protoimpl.UnsafeEnabled {
		mi := &file_fulcio_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CertificateChain) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateChain) ProtoMessage() {}

func (x *CertificateChain) ProtoReflect() protoreflect.Message {
	mi := &file_fulcio_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateChain.ProtoReflect.Descriptor instead.
func (*CertificateChain) Descriptor() ([]byte, []int) {
	return file_fulcio_proto_rawDescGZIP(), []int{8}
}

func (x *CertificateChain) GetCertificates() []string {
	if x != nil {
		return x.Certificates
	}
	return nil
}

var File_fulcio_proto protoreflect.FileDescriptor

var file_fulcio_proto_rawDesc = []byte{
	0x0a, 0x0c, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x16,
	0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c,
	0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69,
	0x2f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe9, 0x01, 0x0a, 0x1f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x4a, 0x0a, 0x0b, 0x63, 0x72, 0x65,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23,
	0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75,
	0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x73, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x45, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f,
	0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x64, 0x65, 0x76, 0x2e,
	0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e,
	0x76, 0x32, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x42, 0x03, 0xe0, 0x41,
	0x02, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x33, 0x0a, 0x13,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x6f, 0x66, 0x5f, 0x70, 0x6f, 0x73, 0x73, 0x65, 0x73, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x11,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x4f, 0x66, 0x50, 0x6f, 0x73, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x22, 0x4e, 0x0a, 0x0b, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73,
	0x12, 0x30, 0x0a, 0x13, 0x6f, 0x69, 0x64, 0x63, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52,
	0x11, 0x6f, 0x69, 0x64, 0x63, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x42, 0x0d, 0x0a, 0x0b, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x73, 0x22, 0x74, 0x0a, 0x09, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12, 0x48,
	0x0a, 0x09, 0x61, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x2a, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x4b, 0x65, 0x79, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x52, 0x09, 0x61,
	0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x1d, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x42, 0x03, 0xe0, 0x41, 0x02, 0x52, 0x07,
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0xa3, 0x02, 0x0a, 0x12, 0x53, 0x69, 0x67, 0x6e,
	0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x7e,
	0x0a, 0x1f, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x63, 0x68, 0x65, 0x64, 0x5f, 0x73, 0x63,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69,
	0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32,
	0x2e, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x63, 0x68, 0x65, 0x64, 0x53, 0x43, 0x54, 0x48, 0x00,
	0x52, 0x1c, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x63, 0x68, 0x65, 0x64, 0x53, 0x63, 0x74, 0x12, 0x7e,
	0x0a, 0x1f, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x5f, 0x65, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x5f, 0x73, 0x63,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69,
	0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32,
	0x2e, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x45, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x53, 0x43, 0x54, 0x48, 0x00,
	0x52, 0x1c, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x45, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x53, 0x63, 0x74, 0x42, 0x0d,
	0x0a, 0x0b, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x22, 0xa1, 0x01,
	0x0a, 0x1d, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
	0x63, 0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x63, 0x68, 0x65, 0x64, 0x53, 0x43, 0x54, 0x12,
	0x3e, 0x0a, 0x05, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x28,
	0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75,
	0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x52, 0x05, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x12,
	0x40, 0x0a, 0x1c, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x1a, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x43, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
	0x70, 0x22, 0x5f, 0x0a, 0x1d, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x45, 0x6d, 0x62, 0x65, 0x64, 0x64, 0x65, 0x64, 0x53,
	0x43, 0x54, 0x12, 0x3e, 0x0a, 0x05, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x28, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x69,
	0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x52, 0x05, 0x63, 0x68, 0x61,
	0x69, 0x6e, 0x22, 0x17, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x54, 0x72, 0x75, 0x73, 0x74, 0x42, 0x75,
	0x6e, 0x64, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x4f, 0x0a, 0x0b, 0x54,
	0x72, 0x75, 0x73, 0x74, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x40, 0x0a, 0x06, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x64, 0x65, 0x76,
	0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f,
	0x2e, 0x76, 0x32, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x43,
	0x68, 0x61, 0x69, 0x6e, 0x52, 0x06, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x73, 0x22, 0x36, 0x0a, 0x10,
	0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x43, 0x68, 0x61, 0x69, 0x6e,
	0x12, 0x22, 0x0a, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
	0x61, 0x74, 0x65, 0x73, 0x2a, 0x5f, 0x0a, 0x12, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65,
	0x79, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x12, 0x24, 0x0a, 0x20, 0x50, 0x55,
	0x42, 0x4c, 0x49, 0x43, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x41, 0x4c, 0x47, 0x4f, 0x52, 0x49, 0x54,
	0x48, 0x4d, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00,
	0x12, 0x0b, 0x0a, 0x07, 0x52, 0x53, 0x41, 0x5f, 0x50, 0x53, 0x53, 0x10, 0x01, 0x12, 0x09, 0x0a,
	0x05, 0x45, 0x43, 0x44, 0x53, 0x41, 0x10, 0x02, 0x12, 0x0b, 0x0a, 0x07, 0x45, 0x44, 0x32, 0x35,
	0x35, 0x31, 0x39, 0x10, 0x03, 0x32, 0xaa, 0x02, 0x0a, 0x02, 0x43, 0x41, 0x12, 0x9f, 0x01, 0x0a,
	0x18, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x37, 0x2e, 0x64, 0x65, 0x76, 0x2e,
	0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e,
	0x76, 0x32, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x53, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
	0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x2a, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72,
	0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x22, 0x1e,
	0x82, 0xd3, 0xe4, 0x93, 0x02, 0x18, 0x22, 0x13, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f,
	0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67, 0x43, 0x65, 0x72, 0x74, 0x3a, 0x01, 0x2a, 0x12, 0x81,
	0x01, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x54, 0x72, 0x75, 0x73, 0x74, 0x42, 0x75, 0x6e, 0x64, 0x6c,
	0x65, 0x12, 0x2d, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x47, 0x65, 0x74, 0x54, 0x72,
	0x75, 0x73, 0x74, 0x42, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x23, 0x2e, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e,
	0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x2e, 0x54, 0x72, 0x75, 0x73, 0x74, 0x42,
	0x75, 0x6e, 0x64, 0x6c, 0x65, 0x22, 0x1b, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x15, 0x12, 0x13, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x76, 0x32, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x42, 0x75, 0x6e, 0x64,
	0x6c, 0x65, 0x42, 0x5a, 0x0a, 0x16, 0x64, 0x65, 0x76, 0x2e, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2e, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2e, 0x76, 0x32, 0x42, 0x0b, 0x46, 0x75,
	0x6c, 0x63, 0x69, 0x6f, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x31, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x2f, 0x66, 0x75, 0x6c, 0x63, 0x69, 0x6f, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x65, 0x64, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_fulcio_proto_rawDescOnce sync.Once
	file_fulcio_proto_rawDescData = file_fulcio_proto_rawDesc
)

func file_fulcio_proto_rawDescGZIP() []byte {
	file_fulcio_proto_rawDescOnce.Do(func() {
		file_fulcio_proto_rawDescData = protoimpl.X.CompressGZIP(file_fulcio_proto_rawDescData)
	})
	return file_fulcio_proto_rawDescData
}

var file_fulcio_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_fulcio_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_fulcio_proto_goTypes = []interface{}{
	(PublicKeyAlgorithm)(0),                 // 0: dev.sigstore.fulcio.v2.PublicKeyAlgorithm
	(*CreateSigningCertificateRequest)(nil), // 1: dev.sigstore.fulcio.v2.CreateSigningCertificateRequest
	(*Credentials)(nil),                     // 2: dev.sigstore.fulcio.v2.Credentials
	(*PublicKey)(nil),                       // 3: dev.sigstore.fulcio.v2.PublicKey
	(*SigningCertificate)(nil),              // 4: dev.sigstore.fulcio.v2.SigningCertificate
	(*SigningCertificateDetachedSCT)(nil),   // 5: dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT
	(*SigningCertificateEmbeddedSCT)(nil),   // 6: dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT
	(*GetTrustBundleRequest)(nil),           // 7: dev.sigstore.fulcio.v2.GetTrustBundleRequest
	(*TrustBundle)(nil),                     // 8: dev.sigstore.fulcio.v2.TrustBundle
	(*CertificateChain)(nil),                // 9: dev.sigstore.fulcio.v2.CertificateChain
}
var file_fulcio_proto_depIdxs = []int32{
	2,  // 0: dev.sigstore.fulcio.v2.CreateSigningCertificateRequest.credentials:type_name -> dev.sigstore.fulcio.v2.Credentials
	3,  // 1: dev.sigstore.fulcio.v2.CreateSigningCertificateRequest.public_key:type_name -> dev.sigstore.fulcio.v2.PublicKey
	0,  // 2: dev.sigstore.fulcio.v2.PublicKey.algorithm:type_name -> dev.sigstore.fulcio.v2.PublicKeyAlgorithm
	5,  // 3: dev.sigstore.fulcio.v2.SigningCertificate.signed_certificate_detached_sct:type_name -> dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT
	6,  // 4: dev.sigstore.fulcio.v2.SigningCertificate.signed_certificate_embedded_sct:type_name -> dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT
	9,  // 5: dev.sigstore.fulcio.v2.SigningCertificateDetachedSCT.chain:type_name -> dev.sigstore.fulcio.v2.CertificateChain
	9,  // 6: dev.sigstore.fulcio.v2.SigningCertificateEmbeddedSCT.chain:type_name -> dev.sigstore.fulcio.v2.CertificateChain
	9,  // 7: dev.sigstore.fulcio.v2.TrustBundle.chains:type_name -> dev.sigstore.fulcio.v2.CertificateChain
	1,  // 8: dev.sigstore.fulcio.v2.CA.CreateSigningCertificate:input_type -> dev.sigstore.fulcio.v2.CreateSigningCertificateRequest
	7,  // 9: dev.sigstore.fulcio.v2.CA.GetTrustBundle:input_type -> dev.sigstore.fulcio.v2.GetTrustBundleRequest
	4,  // 10: dev.sigstore.fulcio.v2.CA.CreateSigningCertificate:output_type -> dev.sigstore.fulcio.v2.SigningCertificate
	8,  // 11: dev.sigstore.fulcio.v2.CA.GetTrustBundle:output_type -> dev.sigstore.fulcio.v2.TrustBundle
	10, // [10:12] is the sub-list for method output_type
	8,  // [8:10] is the sub-list for method input_type
	8,  // [8:8] is the sub-list for extension type_name
	8,  // [8:8] is the sub-list for extension extendee
	0,  // [0:8] is the sub-list for field type_name
}

func init() { file_fulcio_proto_init() }
func file_fulcio_proto_init() {
	if File_fulcio_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_fulcio_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateSigningCertificateRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Credentials); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SigningCertificate); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SigningCertificateDetachedSCT); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SigningCertificateEmbeddedSCT); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetTrustBundleRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TrustBundle); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_fulcio_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CertificateChain); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_fulcio_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*Credentials_OidcIdentityToken)(nil),
	}
	file_fulcio_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*SigningCertificate_SignedCertificateDetachedSct)(nil),
		(*SigningCertificate_SignedCertificateEmbeddedSct)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_fulcio_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_fulcio_proto_goTypes,
		DependencyIndexes: file_fulcio_proto_depIdxs,
		EnumInfos:         file_fulcio_proto_enumTypes,
		MessageInfos:      file_fulcio_proto_msgTypes,
	}.Build()
	File_fulcio_proto = out.File
	file_fulcio_proto_rawDesc = nil
	file_fulcio_proto_goTypes = nil
	file_fulcio_proto_depIdxs = nil
}
