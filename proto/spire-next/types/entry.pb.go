// Code generated by protoc-gen-go. DO NOT EDIT.
// source: spire-next/types/entry.proto

package types

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Entry struct {
	// Globally unique ID for the entry.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The SPIFFE ID of the identity described by this entry.
	SpiffeId *SPIFFEID `protobuf:"bytes,2,opt,name=spiffe_id,json=spiffeId,proto3" json:"spiffe_id,omitempty"`
	// Who the entry is delegated to. If the entry describes a node, this is
	// set to the SPIFFE ID of the SPIRE server of the trust domain (e.g.
	// spiffe://example.org/spire/server). Otherwise, it will be set to a node
	// SPIFFE ID.
	ParentId *SPIFFEID `protobuf:"bytes,3,opt,name=parent_id,json=parentId,proto3" json:"parent_id,omitempty"`
	// The selectors which identify which entities match this entry. If this is
	// an entry for a node, these selectors represent selectors produced by
	// node attestation. Otherwise, these selectors represent those produced by
	// workload attestation.
	Selectors []*Selector `protobuf:"bytes,4,rep,name=selectors,proto3" json:"selectors,omitempty"`
	// The time to live for identities issued for this entry (in seconds).
	Ttl int32 `protobuf:"varint,5,opt,name=ttl,proto3" json:"ttl,omitempty"`
	// The names of trust domains the identity described by this entry
	// federates with.
	FederatesWith []string `protobuf:"bytes,6,rep,name=federates_with,json=federatesWith,proto3" json:"federates_with,omitempty"`
	// Whether or not the identity described by this entry is an administrative
	// workload. Administrative workloads are granted additional access to
	// various managerial server APIs, such as entry registration.
	Admin bool `protobuf:"varint,7,opt,name=admin,proto3" json:"admin,omitempty"`
	// Whether or not the identity described by this entry represents a
	// downstream SPIRE server. Downstream SPIRE servers have additional access
	// to various signing APIs, such as those used to sign X.509 CA
	// certificates and publish JWT signing keys.
	Downstream bool `protobuf:"varint,8,opt,name=downstream,proto3" json:"downstream,omitempty"`
	// When the entry expires (seconds since Unix epoch).
	ExpiresAt int64 `protobuf:"varint,9,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	// A list of DNS names associated with the identity described by this entry.
	DnsNames             []string `protobuf:"bytes,10,rep,name=dns_names,json=dnsNames,proto3" json:"dns_names,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Entry) Reset()         { *m = Entry{} }
func (m *Entry) String() string { return proto.CompactTextString(m) }
func (*Entry) ProtoMessage()    {}
func (*Entry) Descriptor() ([]byte, []int) {
	return fileDescriptor_e0e2bfec39452b8c, []int{0}
}

func (m *Entry) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Entry.Unmarshal(m, b)
}
func (m *Entry) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Entry.Marshal(b, m, deterministic)
}
func (m *Entry) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Entry.Merge(m, src)
}
func (m *Entry) XXX_Size() int {
	return xxx_messageInfo_Entry.Size(m)
}
func (m *Entry) XXX_DiscardUnknown() {
	xxx_messageInfo_Entry.DiscardUnknown(m)
}

var xxx_messageInfo_Entry proto.InternalMessageInfo

func (m *Entry) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Entry) GetSpiffeId() *SPIFFEID {
	if m != nil {
		return m.SpiffeId
	}
	return nil
}

func (m *Entry) GetParentId() *SPIFFEID {
	if m != nil {
		return m.ParentId
	}
	return nil
}

func (m *Entry) GetSelectors() []*Selector {
	if m != nil {
		return m.Selectors
	}
	return nil
}

func (m *Entry) GetTtl() int32 {
	if m != nil {
		return m.Ttl
	}
	return 0
}

func (m *Entry) GetFederatesWith() []string {
	if m != nil {
		return m.FederatesWith
	}
	return nil
}

func (m *Entry) GetAdmin() bool {
	if m != nil {
		return m.Admin
	}
	return false
}

func (m *Entry) GetDownstream() bool {
	if m != nil {
		return m.Downstream
	}
	return false
}

func (m *Entry) GetExpiresAt() int64 {
	if m != nil {
		return m.ExpiresAt
	}
	return 0
}

func (m *Entry) GetDnsNames() []string {
	if m != nil {
		return m.DnsNames
	}
	return nil
}

// Field mask for Entry fields
type EntryMask struct {
	// spiffe_id field mask
	SpiffeId bool `protobuf:"varint,2,opt,name=spiffe_id,json=spiffeId,proto3" json:"spiffe_id,omitempty"`
	// parent_id field mask
	ParentId bool `protobuf:"varint,3,opt,name=parent_id,json=parentId,proto3" json:"parent_id,omitempty"`
	// selectors field mask
	Selectors bool `protobuf:"varint,4,opt,name=selectors,proto3" json:"selectors,omitempty"`
	// ttl field mask
	Ttl bool `protobuf:"varint,5,opt,name=ttl,proto3" json:"ttl,omitempty"`
	// federates_with field mask
	FederatesWith bool `protobuf:"varint,6,opt,name=federates_with,json=federatesWith,proto3" json:"federates_with,omitempty"`
	// admin field mask
	Admin bool `protobuf:"varint,7,opt,name=admin,proto3" json:"admin,omitempty"`
	// downstream field mask
	Downstream bool `protobuf:"varint,8,opt,name=downstream,proto3" json:"downstream,omitempty"`
	// expires_at field mask
	ExpiresAt bool `protobuf:"varint,9,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	// dns_names field mask
	DnsNames             bool     `protobuf:"varint,10,opt,name=dns_names,json=dnsNames,proto3" json:"dns_names,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *EntryMask) Reset()         { *m = EntryMask{} }
func (m *EntryMask) String() string { return proto.CompactTextString(m) }
func (*EntryMask) ProtoMessage()    {}
func (*EntryMask) Descriptor() ([]byte, []int) {
	return fileDescriptor_e0e2bfec39452b8c, []int{1}
}

func (m *EntryMask) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_EntryMask.Unmarshal(m, b)
}
func (m *EntryMask) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_EntryMask.Marshal(b, m, deterministic)
}
func (m *EntryMask) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EntryMask.Merge(m, src)
}
func (m *EntryMask) XXX_Size() int {
	return xxx_messageInfo_EntryMask.Size(m)
}
func (m *EntryMask) XXX_DiscardUnknown() {
	xxx_messageInfo_EntryMask.DiscardUnknown(m)
}

var xxx_messageInfo_EntryMask proto.InternalMessageInfo

func (m *EntryMask) GetSpiffeId() bool {
	if m != nil {
		return m.SpiffeId
	}
	return false
}

func (m *EntryMask) GetParentId() bool {
	if m != nil {
		return m.ParentId
	}
	return false
}

func (m *EntryMask) GetSelectors() bool {
	if m != nil {
		return m.Selectors
	}
	return false
}

func (m *EntryMask) GetTtl() bool {
	if m != nil {
		return m.Ttl
	}
	return false
}

func (m *EntryMask) GetFederatesWith() bool {
	if m != nil {
		return m.FederatesWith
	}
	return false
}

func (m *EntryMask) GetAdmin() bool {
	if m != nil {
		return m.Admin
	}
	return false
}

func (m *EntryMask) GetDownstream() bool {
	if m != nil {
		return m.Downstream
	}
	return false
}

func (m *EntryMask) GetExpiresAt() bool {
	if m != nil {
		return m.ExpiresAt
	}
	return false
}

func (m *EntryMask) GetDnsNames() bool {
	if m != nil {
		return m.DnsNames
	}
	return false
}

func init() {
	proto.RegisterType((*Entry)(nil), "spire.types.Entry")
	proto.RegisterType((*EntryMask)(nil), "spire.types.EntryMask")
}

func init() { proto.RegisterFile("spire-next/types/entry.proto", fileDescriptor_e0e2bfec39452b8c) }

var fileDescriptor_e0e2bfec39452b8c = []byte{
	// 376 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x92, 0xdf, 0x4a, 0xf3, 0x30,
	0x18, 0x87, 0x69, 0xfb, 0x75, 0x5f, 0x92, 0xf1, 0x8d, 0x8f, 0xa0, 0x10, 0xdc, 0xd4, 0x32, 0x10,
	0x7a, 0x62, 0x2b, 0xdb, 0x15, 0x28, 0x6e, 0xd0, 0x03, 0x45, 0xea, 0x81, 0xe0, 0x49, 0xe9, 0x96,
	0xcc, 0x05, 0xd7, 0xb4, 0x34, 0x91, 0x6d, 0x37, 0xe1, 0x2d, 0x7a, 0x2b, 0x92, 0x74, 0xd3, 0xee,
	0x8f, 0x3b, 0xf3, 0xac, 0x79, 0x7f, 0xcf, 0xdb, 0xbc, 0x7d, 0xfa, 0xa2, 0x8e, 0x2c, 0x78, 0xc9,
	0x2e, 0x05, 0x5b, 0xa8, 0x50, 0x2d, 0x0b, 0x26, 0x43, 0x26, 0x54, 0xb9, 0x0c, 0x8a, 0x32, 0x57,
	0x39, 0x6e, 0x9a, 0x34, 0x30, 0xc1, 0xc9, 0xf9, 0x0e, 0x2a, 0xd9, 0x8c, 0x8d, 0x55, 0x5e, 0x56,
	0xf4, 0x3e, 0xa0, 0xe0, 0x93, 0x09, 0xe3, 0xb4, 0x02, 0xba, 0x1f, 0x36, 0x72, 0x07, 0xfa, 0xf5,
	0xb8, 0x85, 0x6c, 0x4e, 0x89, 0xe5, 0x59, 0x3e, 0x8c, 0x6d, 0x4e, 0x71, 0x0f, 0xc1, 0x8a, 0x4d,
	0x38, 0x25, 0xb6, 0x67, 0xf9, 0xcd, 0xde, 0x71, 0x50, 0xbb, 0x3c, 0x78, 0x7c, 0x88, 0x86, 0xc3,
	0x41, 0x74, 0x1b, 0x83, 0x8a, 0x8b, 0x4c, 0x4f, 0x91, 0x96, 0x4c, 0x28, 0xdd, 0xe3, 0x1c, 0xec,
	0xa9, 0xb8, 0x88, 0xe2, 0x3e, 0x82, 0xeb, 0xa1, 0x25, 0xf9, 0xe3, 0x39, 0xbb, 0x3d, 0xab, 0x34,
	0xfe, 0xe6, 0xf0, 0x7f, 0xe4, 0x28, 0x35, 0x23, 0xae, 0x67, 0xf9, 0x6e, 0xac, 0x1f, 0xf1, 0x05,
	0x6a, 0x4d, 0x18, 0x65, 0x65, 0xaa, 0x98, 0x4c, 0xe6, 0x5c, 0x4d, 0x49, 0xc3, 0x73, 0x7c, 0x18,
	0xff, 0xfb, 0xaa, 0x3e, 0x71, 0x35, 0xc5, 0x47, 0xc8, 0x4d, 0x69, 0xc6, 0x05, 0xf9, 0xeb, 0x59,
	0x3e, 0x88, 0xab, 0x03, 0x3e, 0x43, 0x88, 0xe6, 0x73, 0x21, 0x55, 0xc9, 0xd2, 0x8c, 0x00, 0x13,
	0xd5, 0x2a, 0xf8, 0x14, 0x21, 0xb6, 0xd0, 0x23, 0xc9, 0x24, 0x55, 0x04, 0x7a, 0x96, 0xef, 0xc4,
	0x70, 0x55, 0xb9, 0x56, 0xb8, 0x8d, 0x20, 0x15, 0x32, 0x11, 0x69, 0xc6, 0x24, 0x41, 0xe6, 0x5a,
	0x40, 0x85, 0xbc, 0xd7, 0xe7, 0xee, 0xbb, 0x8d, 0xa0, 0x31, 0x7c, 0x97, 0xca, 0x57, 0x8d, 0x6e,
	0x5a, 0x05, 0x35, 0x7d, 0xed, 0x6d, 0x7d, 0xa0, 0xe6, 0xa9, 0xb3, 0xe9, 0x49, 0x87, 0xfb, 0x85,
	0x80, 0x9f, 0x85, 0xe8, 0xf0, 0x97, 0x84, 0x80, 0x03, 0x42, 0xcc, 0x87, 0xac, 0x85, 0xdc, 0x5c,
	0x3d, 0x07, 0x2f, 0x5c, 0x4d, 0xdf, 0x46, 0xc1, 0x38, 0xcf, 0x56, 0xfb, 0x18, 0x9a, 0x1f, 0x1e,
	0x9a, 0x9d, 0x0c, 0xb7, 0x77, 0x76, 0xd4, 0x30, 0xf5, 0xfe, 0x67, 0x00, 0x00, 0x00, 0xff, 0xff,
	0x23, 0x05, 0x1d, 0xbf, 0x1a, 0x03, 0x00, 0x00,
}