/* Copyright 2019 The Subscribe with Google Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	gcmpb "github.com/google/tink/go/proto/aes_gcm_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

// Helper functions for the SwG Encryption Script.

const aesGCMKeyURL string = "type.googleapis.com/google.crypto.tink.AesGcmKey"
const aesGCMKeySize uint32 = 16

type EncryptionResult struct {
	Fragment string            `json:"fragment"`
	Keys     map[string]string `json:"keys"`
}

// Public function to generate an encrypted HTML document given the original.
func GenerateEncryptedFragment(fragment []byte, accessRequirements []string, pubKeys map[string]tinkpb.Keyset) (*EncryptionResult, error) {
	km, err := registry.GetKeyManager(aesGCMKeyURL)
	if err != nil {
		return nil, err
	}
	key, err := generateNewAesGcmKey(km)
	if err != nil {
		return nil, err
	}
	keyBuf, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}
	ks := createAesGcmKeyset(keyBuf)
	kh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: &ks})
	if err != nil {
		return nil, err
	}

	ef, err := encryptFragment(fragment, kh)
	if err != nil {
		return nil, err
	}

	encryptedKeys, err := encryptDocumentKey(key.KeyValue, accessRequirements, pubKeys)
	if err != nil {
		return nil, err
	}

	er := &EncryptionResult{
		Fragment: *ef,
		Keys:     encryptedKeys,
	}

	return er, nil
}

func DecryptCrypt(crypt []byte, ks tinkpb.Keyset) (*string, error) {
	kh, err := insecurecleartextkeyset.Read(&keyset.MemReaderWriter{Keyset: &ks})
	if err != nil {
		return nil, err
	}

	cipher, err := hybrid.NewHybridDecrypt(kh)
	if err != nil {
		return nil, err
	}

	dc, err := cipher.Decrypt(crypt, nil)
	if err != nil {
		return nil, err
	}

	sc := string(dc)

	return &sc, nil
}

// Retrieves a Tink public key from the given URL.
func RetrieveTinkPublicKey(publicKeyURL string) (tinkpb.Keyset, error) {
	resp, err := http.Get(publicKeyURL)
	if err != nil {
		return tinkpb.Keyset{}, err
	}
	r := keyset.NewJSONReader(resp.Body)
	ks, err := r.Read()
	if err != nil {
		return tinkpb.Keyset{}, err
	}
	return *ks, nil
}

func ReadTinkPrivKey(privKeyFile *os.File) (tinkpb.Keyset, error) {
	r := keyset.NewJSONReader(privKeyFile)
	ks, err := r.Read()
	if err != nil {
		return tinkpb.Keyset{}, err
	}
	return *ks, nil
}

// Generates a new AES-GCM key.
func generateNewAesGcmKey(km registry.KeyManager) (*gcmpb.AesGcmKey, error) {
	p, err := proto.Marshal(&gcmpb.AesGcmKeyFormat{KeySize: aesGCMKeySize})
	if err != nil {
		return nil, err
	}
	m, err := km.NewKey(p)
	if err != nil {
		return nil, err
	}
	return m.(*gcmpb.AesGcmKey), nil
}

// Creates an AES-GCM Keyset using the input key.
// Example output proto:
//
//			primary_key_id: 1
//			key: <
//				key_data: <
//	  			type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
//	  			value: "\032\020\355\323'\277\341\241u\020w\322\177\207\357\374\301/"
//	  			key_material_type: SYMMETRIC
//				>
//				status: ENABLED
//				key_id: 1
//				output_prefix_type: TINK
//			>
func createAesGcmKeyset(key []byte) tinkpb.Keyset {
	keyData := tinkpb.KeyData{
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
		TypeUrl:         aesGCMKeyURL,
		Value:           key,
	}
	keys := []*tinkpb.Keyset_Key{
		&tinkpb.Keyset_Key{
			KeyData:          &keyData,
			Status:           tinkpb.KeyStatusType_ENABLED,
			KeyId:            1,
			OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		},
	}
	return tinkpb.Keyset{
		PrimaryKeyId: 1,
		Key:          keys,
	}
}

// Encrypts the content inside of the input "encryptedSections" nodes.
func encryptFragment(b []byte, kh *keyset.Handle) (*string, error) {
	cipher, err := aead.New(kh)
	if err != nil {
		return nil, err
	}

	encContent, err := cipher.Encrypt(b, nil)
	if err != nil {
		return nil, err
	}

	ef := base64.StdEncoding.EncodeToString(encContent)
	return &ef, nil
}

type swgEncryptionKey struct {
	AccessRequirements []string
	Key                string
}

// Encrypts the document's symmetric key using the input Keyset.
func encryptDocumentKey(docKey []byte, accessRequirements []string, pubKeys map[string]tinkpb.Keyset) (map[string]string, error) {
	outMap := make(map[string]string)
	for domain, ks := range pubKeys {
		handle, err := keyset.NewHandleWithNoSecrets(&ks)
		if err != nil {
			return nil, err
		}
		he, err := hybrid.NewHybridEncrypt(handle)
		if err != nil {
			return nil, err
		}
		swgKey := swgEncryptionKey{
			AccessRequirements: accessRequirements,
			Key:                base64.StdEncoding.EncodeToString(docKey),
		}
		jsonData, err := json.Marshal(swgKey)
		if err != nil {
			return nil, err
		}
		enc, err := he.Encrypt(jsonData, nil)
		if err != nil {
			return nil, err
		}
		outMap[domain] = base64.URLEncoding.EncodeToString(enc)
	}
	return outMap, nil
}
