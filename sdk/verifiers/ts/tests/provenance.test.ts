// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import * as ed25519 from "@noble/ed25519";
import test from "node:test";
import { verifyProvenanceFixture } from "../src/provenance.js";

const profileDigest = "sha256:8bc27d5d89e4e5ba3e0d1e68a25a3f0170f9a5ea2f19edf81a9a90bf82e23b3e";
const commitment = `hmac-sha256:${"0".repeat(64)}`;
const seed = Buffer.from("1".repeat(64), "hex");

async function fixture(
  signed: Record<string, unknown>[],
  options: { corruptSignature?: boolean; source?: string } = {},
): Promise<string> {
  const signer = await ed25519.getPublicKeyAsync(seed);
  const entries = await Promise.all(
    signed.map(async (value, index) => {
      const bytes = Buffer.from(JSON.stringify(value));
      const signature = Buffer.from(await ed25519.signAsync(bytes, seed));
      if (options.corruptSignature === true && index === 0) signature[0] ^= 1;
      return {
        signed_b64: bytes.toString("base64"),
        signature: `ed25519:${signature.toString("hex")}`,
      };
    }),
  );
  return JSON.stringify({
    format: "pipelock-evidence-provenance-verification-fixture/v1",
    entries,
    verification: {
      signer_public_key_hex: Buffer.from(signer).toString("hex"),
      sources: [
        {
          source_id: "source-1",
          bytes_b64: Buffer.from(options.source ?? "A💩B").toString("base64"),
        },
      ],
    },
  });
}

function signed(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    chain_seq: 0,
    chain_prev_hash: "genesis",
    critical_features: ["evidence_provenance"],
    proof: {
      version: "pipelock-evidence-provenance-proof/v1",
      transform_profile_digest: profileDigest,
      producer: {},
      sources: [
        {
          source_ordinal: 1,
          source_id: "source-1",
          recipe: { transform_profile_digest: profileDigest, operations: [{ kind: "identity" }] },
          view_commitment: commitment,
          matches: [],
        },
      ],
    },
    ...overrides,
  };
}

test("provenance fixture reports all available stages and remains incomplete without source commitments", async () => {
  const report = await verifyProvenanceFixture(await fixture([signed()]));
  assert.deepEqual(report, {
    signature: "verified",
    chain: "verified",
    artifacts: "matched",
    source_commitment: "not_checked",
    view_reproduction: "reproduced",
    location: "exact_coordinates",
    match_commitment: "not_checked",
    overall: "incomplete",
  });
});

test("provenance fixture fails closed at the critical-feature stage", async () => {
  const report = await verifyProvenanceFixture(await fixture([signed({ critical_features: [] })]));
  assert.equal(report.failure_stage, "critical_features");
  assert.equal(report.signature, "verified");
  assert.equal(report.chain, "verified");
  assert.equal(report.overall, "invalid");
});

test("provenance fixture authenticates a missing critical feature before rejecting it", async () => {
  const proof = signed();
  delete proof.critical_features;
  const report = await verifyProvenanceFixture(await fixture([proof]));
  assert.equal(report.failure_stage, "critical_features");
  assert.equal(report.signature, "verified");
  assert.equal(report.chain, "verified");
});

test("provenance fixture rejects a UTF-8 continuation-byte coordinate", async () => {
  const proof = signed();
  const source = (proof.proof as { sources: Array<Record<string, unknown>> }).sources[0]!;
  source.matches = [
    {
      match_ordinal: 1,
      byte_start: 2,
      byte_end: 5,
      match_class: "credential",
      match_commitment: commitment,
    },
  ];
  const report = await verifyProvenanceFixture(await fixture([proof]));
  assert.equal(report.failure_stage, "location");
  assert.equal(report.location, "mismatch");
});

test("provenance fixture reports signature failure before every later stage", async () => {
  const report = await verifyProvenanceFixture(
    await fixture([signed()], { corruptSignature: true }),
  );
  assert.deepEqual(report, {
    signature: "invalid",
    chain: "not_checked",
    artifacts: "attested_unchecked",
    source_commitment: "not_checked",
    view_reproduction: "not_checked",
    location: "not_checked",
    match_commitment: "not_checked",
    overall: "invalid",
    failure_stage: "signature",
  });
});

test("provenance fixture verifies every entry in a signed chain", async () => {
  const first = signed();
  const prior = `sha256:${createHash("sha256")
    .update(Buffer.from(JSON.stringify(first)))
    .digest("hex")}`;
  const second = signed({ chain_seq: 1, chain_prev_hash: prior });
  const report = await verifyProvenanceFixture(await fixture([first, second]));
  assert.equal(report.signature, "verified");
  assert.equal(report.chain, "verified");
  assert.equal(report.overall, "incomplete");
});

test("provenance fixture marks a signed chain break invalid", async () => {
  const report = await verifyProvenanceFixture(
    await fixture([signed({ chain_prev_hash: "sha256:" + "0".repeat(64) })]),
  );
  assert.equal(report.failure_stage, "chain");
  assert.equal(report.chain, "invalid");
});

test("provenance fixture reports an absent source as incomplete", async () => {
  const value = JSON.parse(await fixture([signed()])) as { verification: Record<string, unknown> };
  delete value.verification.sources;
  const report = await verifyProvenanceFixture(JSON.stringify(value));
  assert.deepEqual(
    {
      signature: report.signature,
      chain: report.chain,
      artifacts: report.artifacts,
      view_reproduction: report.view_reproduction,
      location: report.location,
      match_commitment: report.match_commitment,
      overall: report.overall,
    },
    {
      signature: "verified",
      chain: "verified",
      artifacts: "matched",
      view_reproduction: "not_checked",
      location: "not_checked",
      match_commitment: "not_checked",
      overall: "incomplete",
    },
  );
});

test("artifact mismatch outranks a distinct unavailable artifact", async () => {
  const proof = signed();
  const producer = (proof.proof as { producer: Record<string, string> }).producer;
  const binary = Buffer.from("matching binary");
  producer.binary_digest = `sha256:${createHash("sha256").update(binary).digest("hex")}`;
  producer.ruleset_digest = `sha256:${"a".repeat(64)}`;
  const value = JSON.parse(await fixture([proof])) as { verification: Record<string, unknown> };
  value.verification.binary_b64 = binary.toString("base64");
  value.verification.ruleset_b64 = Buffer.from("wrong ruleset").toString("base64");
  const report = await verifyProvenanceFixture(JSON.stringify(value));
  assert.equal(report.failure_stage, "artifacts");
  assert.equal(report.artifacts, "mismatch");
});

test("a missing source cannot hide an available sibling reconstruction mismatch", async () => {
  const proof = signed();
  const sources = (proof.proof as { sources: Array<Record<string, unknown>> }).sources;
  sources[0]!.recipe = {
    transform_profile_digest: profileDigest,
    operations: [{ kind: "percent_decode", passes: 1 }],
  };
  sources.push({
    source_ordinal: 2,
    source_id: "source-2",
    recipe: { transform_profile_digest: profileDigest, operations: [{ kind: "identity" }] },
    view_commitment: commitment,
    matches: [],
  });
  const report = await verifyProvenanceFixture(await fixture([proof], { source: "%ff" }));
  assert.equal(report.failure_stage, "view_reproduction");
  assert.equal(report.view_reproduction, "mismatch");
  assert.equal(report.overall, "invalid");
});
