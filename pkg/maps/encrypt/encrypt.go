// Copyright 2018 Authors of Cilium
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

package encrypt

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EncryptKey is the context ID for the encryption session
type EncryptKey struct {
	key uint32 `align:"ctx"`
}

// EncryptValue is ID assigned to the keys
type EncryptValue struct {
	encryptKeyID uint8
}

// String pretty print the EncryptKey
func (k EncryptKey) String() string {
	return fmt.Sprintf("%d", k.key)
}

// String pretty print the encyrption key index.
func (v EncryptValue) String() string {
	return fmt.Sprintf("%d", v.encryptKeyID)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v EncryptValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(&v) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k EncryptKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure represeting the BPF
// map value
func (k EncryptKey) NewValue() bpf.MapValue { return &EncryptValue{} }

func newEncryptKey(key uint32) *EncryptKey {
	return &EncryptKey{
		key: key,
	}
}

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "encryptMap")

const (
	// MapName name of map used to pin map for datapath
	MapName = "cilium_encrypt_state"

	// MaxEntries represents the maximum number of current encryption contexts
	MaxEntries = 1
)

var (
	// Encrypt represents the BPF map for sockets
	encryptMap = bpf.NewMap(MapName,
		bpf.MapTypeArray,
		int(unsafe.Sizeof(EncryptKey{})),
		int(unsafe.Sizeof(EncryptValue{})),
		MaxEntries,
		0, 0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := EncryptKey{}, EncryptValue{}
			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return k, v, nil
		},
	).WithCache()
)

// MapCreate will create an encrypt map
func MapCreate() {
	encryptMap.OpenOrCreate()
}

// MapUpdateContext updates the encrypt state with ctxID to use the new keyID
func MapUpdateContext(ctxID uint32, keyID uint8) error {
	k := newEncryptKey(ctxID)
	v := &EncryptValue{
		encryptKeyID: keyID,
	}
	return encryptMap.Update(k, v)
}
