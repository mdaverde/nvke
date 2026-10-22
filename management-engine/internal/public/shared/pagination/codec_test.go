// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Codec tests protect cursor isolation, bounded decoding and compatibility across replicas.
package pagination

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/management-engine/internal/public/shared/limits"
)

// TestConfiguration rejects unusable keys and ambiguous scope configuration before issuing tokens.
func TestConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyLen int
		scope  []string
		valid  bool
	}{
		{name: "minimum key", keyLen: limits.PageTokenKeyMinBytes, scope: []string{"list-v1", "storage"}, valid: true},
		{name: "maximum key", keyLen: limits.PageTokenKeyMaxBytes, scope: []string{"list-v1", "storage"}, valid: true},
		{name: "missing key", scope: []string{"list-v1", "storage"}},
		{name: "short key", keyLen: limits.PageTokenKeyMinBytes - 1, scope: []string{"list-v1", "storage"}},
		{name: "long key", keyLen: limits.PageTokenKeyMaxBytes + 1, scope: []string{"list-v1", "storage"}},
		{name: "missing scope", keyLen: limits.PageTokenKeyMinBytes},
		{name: "domain only", keyLen: limits.PageTokenKeyMinBytes, scope: []string{"list-v1"}},
		{name: "empty domain", keyLen: limits.PageTokenKeyMinBytes, scope: []string{"", "storage"}},
		{name: "empty scope component", keyLen: limits.PageTokenKeyMinBytes, scope: []string{"list-v1", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(make([]byte, tc.keyLen), tc.scope)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// TestPageTokens verifies secrecy, scope isolation, expiration and bounds independently of list policy.
func TestPageTokens(t *testing.T) {
	key := make([]byte, limits.PageTokenKeyMinBytes)
	scope := []string{"list-v1", "storage", "collection"}
	codec, err := New(key, scope)
	require.NoError(t, err)
	want := Cursor{Continue: "private-storage-namespace-and-key", Size: 200}
	token, err := codec.Encode(want.Continue, want.Size)
	require.NoError(t, err)
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(token)
	require.NoError(t, err)
	assert.NotContains(t, string(sealed), want.Continue)
	resumed, err := New(key, scope)
	require.NoError(t, err)
	got, err := resumed.Decode(token)
	require.NoError(t, err)
	assert.Equal(t, want, got, "replicas resume cursors without imposing a resource's page-size maximum")
	for _, tc := range []struct {
		name  string
		key   []byte
		scope []string
	}{
		{name: "domain", key: key, scope: []string{"another-list-v1", "storage", "collection"}},
		{name: "scope", key: key, scope: []string{"list-v1", "another-storage", "collection"}},
		{name: "key", key: []byte(strings.Repeat("k", limits.PageTokenKeyMinBytes)), scope: scope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other, err := New(tc.key, tc.scope)
			require.NoError(t, err)
			_, err = other.Decode(token)
			require.Error(t, err)
		})
	}
	for _, tc := range []struct {
		name   string
		cursor pageCursor
	}{
		{name: "expired", cursor: pageCursor{Cursor: want, Expires: time.Now().Add(-time.Minute).Unix()}},
		{name: "empty position", cursor: pageCursor{Size: 2, Expires: time.Now().Add(time.Minute).Unix()}},
		{name: "nonpositive size", cursor: pageCursor{Continue: want.Continue, Expires: time.Now().Add(time.Minute).Unix()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.cursor)
			require.NoError(t, err)
			sealed := codec.tokens.Seal(nil, nil, data, codec.scope) // #nosec G407 -- NewGCMWithRandomNonce requires nil.
			_, err = codec.Decode(base64.RawURLEncoding.EncodeToString(sealed))
			require.Error(t, err)
		})
	}
	for name, invalid := range map[string]string{
		"malformed": "A" + token,
		"short":     "AA",
		"oversized": strings.Repeat("A", maxTokenBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := codec.Decode(invalid)
			require.Error(t, err)
		})
	}
	_, err = codec.Encode(strings.Repeat("x", maxTokenBytes), 2)
	require.Error(t, err, "oversized cursors cannot produce tokens that decoding would reject")
}

// TestPageTokenWireCompatibility checks the token format independently so replicas can resume each other's lists.
func TestPageTokenWireCompatibility(t *testing.T) {
	key := make([]byte, limits.PageTokenKeyMinBytes)
	codec, err := New(key, []string{"cluster-list-v1", "test-storage", "default"})
	require.NoError(t, err)
	digest := sha256.Sum256(key)
	block, err := aes.NewCipher(digest[:])
	require.NoError(t, err)
	legacy, err := cipher.NewGCM(block)
	require.NoError(t, err)
	// Keep the old wire schema and associated data independent of production types.
	type legacyCursor struct {
		Continue string `json:"continue"`
		Size     int32  `json:"size"`
		Expires  int64  `json:"expires"`
	}
	scope := []byte(`["cluster-list-v1","test-storage","default"]`)
	want := legacyCursor{Continue: "storage-cursor", Size: 2, Expires: time.Now().Add(time.Minute).Unix()}
	data, err := json.Marshal(want)
	require.NoError(t, err)
	nonce := make([]byte, legacy.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	sealed := legacy.Seal(nonce, nonce, data, scope)
	decoded, err := codec.Decode(base64.RawURLEncoding.EncodeToString(sealed))
	require.NoError(t, err)
	assert.Equal(t, want.Continue, decoded.Continue)
	assert.Equal(t, want.Size, decoded.Size)
	sealed[len(sealed)-1] ^= 1
	_, err = codec.Decode(base64.RawURLEncoding.EncodeToString(sealed))
	require.Error(t, err, "authenticated payload changes must be rejected")

	token, err := codec.Encode(want.Continue, want.Size)
	require.NoError(t, err)
	sealed, err = base64.RawURLEncoding.Strict().DecodeString(token)
	require.NoError(t, err)
	data, err = legacy.Open(nil, sealed[:legacy.NonceSize()], sealed[legacy.NonceSize():], scope)
	require.NoError(t, err, "older replicas must accept tokens issued by a newer replica")
	var legacyDecoded legacyCursor
	require.NoError(t, json.Unmarshal(data, &legacyDecoded))
	assert.Equal(t, want.Continue, legacyDecoded.Continue)
	assert.Equal(t, want.Size, legacyDecoded.Size)
	assert.Greater(t, legacyDecoded.Expires, time.Now().Unix())
}
