// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestCommittedProvenanceCorpusCoverageAndKnownAnswers(t *testing.T) {
	dir := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "provenance"))
	fixtures, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	caseCount := 0
	operationCount := 0
	propertyCount := 0
	for _, path := range fixtures {
		if strings.HasSuffix(path, ".expect.json") {
			continue
		}
		caseCount++
		base := filepath.Base(path)
		if strings.HasPrefix(base, "o") {
			operationCount++
		}
		if strings.HasPrefix(base, "r") {
			propertyCount++
		}
		if _, err := os.Stat(strings.TrimSuffix(path, ".json") + ".expect.json"); err != nil {
			t.Fatalf("%s lacks exact expected staged output: %v", base, err)
		}
	}
	if caseCount != 58 || operationCount != len(normalize.SupportedOperationKinds()) || propertyCount != 16 {
		t.Fatalf("corpus counts = cases %d operations %d properties %d; want 58, %d, 16", caseCount, operationCount, propertyCount, len(normalize.SupportedOperationKinds()))
	}

	data, err := os.ReadFile(filepath.Join(dir, "p00-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture provenanceFixture
	if err := decodeStrictJSON(data, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedProvenanceProof
	if err := decodeStrictJSON(raw, &signed); err != nil {
		t.Fatal(err)
	}
	const knownView = "hmac-sha256:f460ac62bff21205d2a65039711cf06b80f210735c97e0fcb081c65b66586631"
	const knownMatch = "hmac-sha256:7992f8156982a6588a6f26ddadc9add33d8ef1be1b8c0dc86b2349038cdc870e"
	if signed.Proof.Sources[0].ViewCommitment != knownView || signed.Proof.Sources[0].Matches[0].MatchCommitment != knownMatch {
		t.Fatalf("known-answer commitments drifted: view %q match %q", signed.Proof.Sources[0].ViewCommitment, signed.Proof.Sources[0].Matches[0].MatchCommitment)
	}
}

// TestGenerateProvenanceCorpus is an explicit, deterministic fixture writer.
// Normal test runs only exercise the committed corpus through the cross-language
// gate; regeneration requires UPDATE_PROVENANCE_FIXTURES=1.
func TestGenerateProvenanceCorpus(t *testing.T) {
	if os.Getenv("UPDATE_PROVENANCE_FIXTURES") != "1" {
		t.Skip("set UPDATE_PROVENANCE_FIXTURES=1 to regenerate fixtures")
	}
	dir := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "provenance"))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	baseline := corpusFixture(t, normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, "A💩B", 1, 5)
	writeProvenanceCase(t, dir, "p00-valid", baseline)

	chain := cloneCorpusFixture(t, baseline)
	appendCorpusEntry(t, &chain)
	writeProvenanceCase(t, dir, "p01-valid-chain", chain)

	signature := cloneCorpusFixture(t, baseline)
	signature.Entries[0].Signature = "ed25519:" + repeatHexByte(0, ed25519.SignatureSize)
	writeProvenanceCase(t, dir, "p02-signature-invalid", signature)

	for _, tc := range []struct {
		id     string
		mutate func(*signedProvenanceProof, *provenanceFixture)
	}{
		{"p03-chain-sequence", func(s *signedProvenanceProof, _ *provenanceFixture) { s.ChainSeq = 1 }},
		{"p03b-chain-previous-hash", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.ChainPrevHash = "sha256:" + repeatHexByte(0, sha256.Size)
		}},
		{"p04-critical-missing", func(s *signedProvenanceProof, _ *provenanceFixture) { s.CriticalFeatures = nil }},
		{"p05-critical-unknown", func(s *signedProvenanceProof, _ *provenanceFixture) { s.CriticalFeatures = []string{"unknown"} }},
		{"p06-critical-duplicate", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.CriticalFeatures = []string{provenanceFeature, provenanceFeature}
		}},
		{"p07-proof-version", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Version = "pipelock-evidence-provenance-proof/v2"
		}},
		{"p08-profile-digest", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.TransformProfileDigest = "sha256:" + repeatHexByte(0xaa, sha256.Size)
		}},
		{"p09-source-ordinal-context", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].SourceOrdinal = 2 }},
		{"p10-source-id-context", func(s *signedProvenanceProof, f *provenanceFixture) {
			s.Proof.Sources[0].SourceID = "renamed"
			f.Verification.Sources[0].SourceID = "renamed"
		}},
		{"p11-match-ordinal-context", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].MatchOrdinal = 2 }},
		{"p12-match-class-context", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].Matches[0].MatchClass = "token"
		}},
		{"p13-view-commitment", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].ViewCommitment = "hmac-sha256:" + repeatHexByte(0, sha256.Size)
		}},
		{"p14-match-commitment", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].Matches[0].MatchCommitment = "hmac-sha256:" + repeatHexByte(0, sha256.Size)
		}},
		{"p15-coordinate-start-boundary", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteStart = 2 }},
		{"p16-coordinate-end-boundary", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteEnd = 4 }},
		{"p17-coordinate-out-of-bounds", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteEnd = 7 }},
		{"p18-coordinate-context", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteStart = 0 }},
		{"p19-source-bytes-context", func(_ *signedProvenanceProof, f *provenanceFixture) {
			f.Verification.Sources[0].BytesB64 = base64.StdEncoding.EncodeToString([]byte("Z💩B"))
		}},
		{"p20-wrong-commitment-key", func(_ *signedProvenanceProof, f *provenanceFixture) {
			f.Verification.CommitmentKeyHex = repeatHexByte(0xbb, sha256.Size)
		}},
		{"p21-missing-source", func(_ *signedProvenanceProof, f *provenanceFixture) { f.Verification.Sources = nil }},
		{"p22-missing-commitment-key", func(_ *signedProvenanceProof, f *provenanceFixture) { f.Verification.CommitmentKeyHex = "" }},
	} {
		fixture := cloneCorpusFixture(t, baseline)
		mutateCorpusFixture(t, &fixture, tc.mutate)
		writeProvenanceCase(t, dir, tc.id, fixture)
	}

	binary := "fixture-binary"
	rules := "fixture-rules"
	artifacts := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &artifacts, func(s *signedProvenanceProof, f *provenanceFixture) {
		binarySum := sha256.Sum256([]byte(binary))
		rulesSum := sha256.Sum256([]byte(rules))
		s.Proof.Producer.BinaryDigest = stringRef("sha256:" + hex.EncodeToString(binarySum[:]))
		s.Proof.Producer.RulesetDigest = stringRef("sha256:" + hex.EncodeToString(rulesSum[:]))
		f.Verification.BinaryB64 = stringRef(base64.StdEncoding.EncodeToString([]byte(binary)))
		f.Verification.RulesetB64 = stringRef(base64.StdEncoding.EncodeToString([]byte(rules)))
	})
	writeProvenanceCase(t, dir, "p23-artifacts-matched", artifacts)
	artifactMismatch := cloneCorpusFixture(t, artifacts)
	artifactMismatch.Verification.BinaryB64 = stringRef(base64.StdEncoding.EncodeToString([]byte("wrong")))
	writeProvenanceCase(t, dir, "p24-artifact-digest", artifactMismatch)
	artifactUnchecked := cloneCorpusFixture(t, artifacts)
	artifactUnchecked.Verification.BinaryB64 = nil
	writeProvenanceCase(t, dir, "p25-artifact-unchecked", artifactUnchecked)
	artifactMismatchAfterUnavailable := cloneCorpusFixture(t, artifacts)
	artifactMismatchAfterUnavailable.Verification.BinaryB64 = nil
	artifactMismatchAfterUnavailable.Verification.RulesetB64 = stringRef(base64.StdEncoding.EncodeToString([]byte("wrong")))
	writeProvenanceCase(t, dir, "p26-artifact-mismatch-after-unavailable", artifactMismatchAfterUnavailable)

	sourceMismatchAfterUnavailable := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &sourceMismatchAfterUnavailable, func(s *signedProvenanceProof, f *provenanceFixture) {
		commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		input := "second-view"
		second := s.Proof.Sources[0]
		second.SourceOrdinal = 2
		second.SourceID = "second-source"
		second.Matches = []contractreceipt.ProvenanceMatch{}
		var err error
		second.ViewCommitment, err = contractreceipt.CommitView(commitmentKey[:], second, input)
		if err != nil {
			t.Fatal(err)
		}
		match := contractreceipt.ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 6, MatchClass: "credential"}
		match.MatchCommitment, err = contractreceipt.CommitMatch(commitmentKey[:], second.SourceID, second.Recipe, second.ViewCommitment, match)
		if err != nil {
			t.Fatal(err)
		}
		second.Matches = []contractreceipt.ProvenanceMatch{match}
		s.Proof.Sources = append(s.Proof.Sources, second)
		f.Verification.Sources = []provenanceFixtureSource{{SourceID: second.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte("second-viex"))}}
	})
	writeProvenanceCase(t, dir, "p27-source-mismatch-after-unavailable", sourceMismatchAfterUnavailable)

	missingThenValid := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &missingThenValid, func(s *signedProvenanceProof, f *provenanceFixture) {
		commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		input := "second-view"
		second := s.Proof.Sources[0]
		second.SourceOrdinal = 2
		second.SourceID = "second-source"
		second.Matches = []contractreceipt.ProvenanceMatch{}
		var err error
		second.ViewCommitment, err = contractreceipt.CommitView(commitmentKey[:], second, input)
		if err != nil {
			t.Fatal(err)
		}
		s.Proof.Sources = append(s.Proof.Sources, second)
		f.Verification.Sources = []provenanceFixtureSource{{SourceID: second.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte(input))}}
	})
	writeProvenanceCase(t, dir, "p28-missing-source-before-valid-source", missingThenValid)

	duplicateSignedKey := cloneCorpusFixture(t, baseline)
	raw, err := base64.StdEncoding.DecodeString(duplicateSignedKey.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`{"chain_seq":0,`), []byte(`{"chain_seq":0,"chain_seq":0,`), 1)
	if bytes.Count(raw, []byte(`"chain_seq":0`)) != 2 {
		t.Fatal("failed to construct duplicate signed chain_seq key")
	}
	privateKey := provenanceFixtureSigningKey()
	duplicateSignedKey.Entries[0] = provenanceFixtureEntry{
		SignedB64: base64.StdEncoding.EncodeToString(raw),
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw)),
	}
	writeProvenanceCase(t, dir, "p29-duplicate-signed-key", duplicateSignedKey)

	operationCases := successfulOperationCases()
	for index, operationCase := range operationCases {
		fixture := corpusFixture(t, operationCase.recipe, operationCase.input, 0, uint64(len(operationCase.output)))
		mutateCorpusFixture(t, &fixture, func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].Recipe.Operations = append(s.Proof.Sources[0].Recipe.Operations, normalize.Operation{Kind: normalize.OperationIdentity})
		})
		writeProvenanceCase(t, dir, "o"+twoDigits(index)+"-"+operationCase.name+"-recipe-context", fixture)
	}

	for seed := 0; seed < 16; seed++ {
		input := "prefix-" + strconv.Itoa(seed) + "-💩-suffix"
		fixture := corpusFixture(t, normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, input, 0, 6)
		fixture.Verification.Sources[0].BytesB64 = base64.StdEncoding.EncodeToString([]byte(input[:len(input)-6] + "tuffix"))
		writeProvenanceCase(t, dir, "r"+twoDigits(seed)+"-deterministic-property", fixture)
	}
}

type corpusOperationCase struct {
	name   string
	recipe normalize.Recipe
	input  string
	output string
}

func successfulOperationCases() []corpusOperationCase {
	digest := normalize.EvidenceProvenanceProfileV1Digest
	return []corpusOperationCase{
		{"identity", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, "Value", "Value"},
		// The query parameter is deliberately named "q" rather than a credential
		// word. This case only exercises repeated-parameter occurrence selection,
		// and a name like "token" makes the dogfood self-scan flag the fixture as
		// a credential in a URL, which is a false positive on the parameter name.
		{"url-component", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationURLComponent, Component: normalize.ComponentQueryVal, Selector: "q", Occurrence: 1}}}, "https://api.vendor.example/?q=first&q=second", "second"},
		{"percent-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationPercentDecode, Passes: 2}}}, "%2561", "a"},
		{"dlp-normalize", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationDLPNormalize, Profile: "pipelock-dlp-v1"}}}, "Ｓｅｃｒｅｔ", "Secret"},
		{"lowercase", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationLowercase}}}, "VaLuE", "value"},
		{"invisible-strip", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationInvisibleStrip}}}, "se\u200bcret", "secret"},
		{"hex-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationHexDecode}}}, "76616c7565", "value"},
		{"base32-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationBase32Decode, DecodePadding: true}}}, "OZQWY5LF", "value"},
		{"base64-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationBase64Decode, DecodePadding: true}}}, "dmFsdWU=", "value"},
		{"leetspeak", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationLeetspeak}}}, "s3cr3t", "secret"},
		{"vowel-fold", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationVowelFold}}}, "ignore", "agnara"},
	}
}

func corpusFixture(t *testing.T, recipe normalize.Recipe, input string, start, end uint64) provenanceFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
	source := contractreceipt.ProvenanceSource{SourceOrdinal: 1, SourceID: "fixture-source", Recipe: recipe}
	view, err := recipe.Apply(input)
	if err != nil {
		t.Fatal(err)
	}
	source.ViewCommitment, err = contractreceipt.CommitView(commitmentKey[:], source, view)
	if err != nil {
		t.Fatal(err)
	}
	match := contractreceipt.ProvenanceMatch{MatchOrdinal: 1, ByteStart: start, ByteEnd: end, MatchClass: "credential"}
	match.MatchCommitment, err = contractreceipt.CommitMatch(commitmentKey[:], source.SourceID, recipe, source.ViewCommitment, match)
	if err != nil {
		t.Fatal(err)
	}
	source.Matches = []contractreceipt.ProvenanceMatch{match}
	proof := contractreceipt.EvidenceProvenanceProof{Version: contractreceipt.EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []contractreceipt.ProvenanceSource{source}}
	signed := signedProvenanceProof{ChainSeq: 0, ChainPrevHash: "genesis", CriticalFeatures: []string{provenanceFeature}, Proof: proof}
	raw := corpusMustJSON(t, signed)
	return provenanceFixture{Format: provenanceFixtureFormat, Entries: []provenanceFixtureEntry{{SignedB64: base64.StdEncoding.EncodeToString(raw), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw))}}, Verification: provenanceVerificationInputs{SignerPublicKeyHex: hex.EncodeToString(publicKey), CommitmentKeyHex: hex.EncodeToString(commitmentKey[:]), Sources: []provenanceFixtureSource{{SourceID: source.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte(input))}}}}
}

func mutateCorpusFixture(t *testing.T, fixture *provenanceFixture, mutate func(*signedProvenanceProof, *provenanceFixture)) {
	t.Helper()
	var signed signedProvenanceProof
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	mutate(&signed, fixture)
	raw = corpusMustJSON(t, signed)
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	fixture.Entries[0] = provenanceFixtureEntry{SignedB64: base64.StdEncoding.EncodeToString(raw), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw))}
}

func appendCorpusEntry(t *testing.T, fixture *provenanceFixture) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedProvenanceProof
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	signed.ChainSeq = 1
	signed.ChainPrevHash = "sha256:" + hex.EncodeToString(sum[:])
	next := corpusMustJSON(t, signed)
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	fixture.Entries = append(fixture.Entries, provenanceFixtureEntry{SignedB64: base64.StdEncoding.EncodeToString(next), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, next))})
}

func writeProvenanceCase(t *testing.T, dir, id string, fixture provenanceFixture) {
	t.Helper()
	writeJSONFile(t, filepath.Join(dir, id+".json"), fixture)
	// Expected staged reports are normative known answers, not generated
	// output. Recomputing them through the Go verifier would let a shared bug
	// bless itself during regeneration and make four-way agreement vacuous.
	// New cases require a separately reviewed, hand-authored .expect.json file.
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func corpusMustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneCorpusFixture(t *testing.T, value provenanceFixture) provenanceFixture {
	t.Helper()
	data := corpusMustJSON(t, value)
	var clone provenanceFixture
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func repeatHexByte(value byte, count int) string {
	values := make([]byte, count)
	for index := range values {
		values[index] = value
	}
	return hex.EncodeToString(values)
}

func stringRef(value string) *string { return &value }

func twoDigits(value int) string {
	if value < 10 {
		return "0" + strconv.Itoa(value)
	}
	return strconv.Itoa(value)
}
