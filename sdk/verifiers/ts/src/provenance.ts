// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Fixture-only evidence-provenance proof verifier. This deliberately verifies
// the experimental PR3 proof shape without registering a production receipt
// payload or changing the ordinary receipt verifier.

import { createHash, createHmac } from "node:crypto";
import * as ed25519 from "@noble/ed25519";
import { readFileSync } from "node:fs";
import { RawNumber, parseJSONStrict } from "./aarp/strictjson.js";

export const provenanceFixtureFormat = "pipelock-evidence-provenance-verification-fixture/v1";
const proofVersion = "pipelock-evidence-provenance-proof/v1";
const profileDigest = "sha256:8bc27d5d89e4e5ba3e0d1e68a25a3f0170f9a5ea2f19edf81a9a90bf82e23b3e";
const knownFeature = "evidence_provenance";
const maxInputBytes = 2 << 20;
const maxOutputBytes = 1 << 20;

type SignatureStage = "verified" | "invalid" | "not_checked";
type ChainStage = "verified" | "invalid" | "not_checked";
type ArtifactStage = "matched" | "mismatch" | "attested_unchecked";
type OpenStage = "opened" | "mismatch" | "not_checked";
type ReproductionStage = "reproduced" | "mismatch" | "not_checked";
type LocationStage = "exact_coordinates" | "mismatch" | "not_checked";
type OverallStage = "verified" | "invalid" | "incomplete";
export type FailureStage =
  | "signature"
  | "chain"
  | "critical_features"
  | "proof_structure"
  | "artifacts"
  | "view_reproduction"
  | "location"
  | "view_commitment"
  | "match_commitment";

export interface ProvenanceReport {
  signature: SignatureStage;
  chain: ChainStage;
  artifacts: ArtifactStage;
  source_commitment: OpenStage;
  view_reproduction: ReproductionStage;
  location: LocationStage;
  match_commitment: OpenStage;
  overall: OverallStage;
  failure_stage?: FailureStage;
}

interface Operation {
  kind: string;
  component: string;
  selector: string;
  occurrence: number;
  passes: number;
  profile: string;
  decode_padding: boolean;
}

interface Match {
  match_ordinal: bigint;
  byte_start: bigint;
  byte_end: bigint;
  match_class: string;
  match_commitment: string;
}

interface Source {
  source_ordinal: bigint;
  source_id: string;
  recipe: { transform_profile_digest: string; operations: Operation[] };
  view_commitment: string;
  matches: Match[];
}

interface Proof {
  version: string;
  transform_profile_digest: string;
  sources: Source[];
  producer: { binary_digest?: string; ruleset_digest?: string };
}

interface SignedEntry {
  bytes: Buffer;
  signature: Buffer;
  chain_seq: bigint;
  chain_prev_hash: string;
  critical_features: string[];
  proof: Proof;
}

interface Fixture {
  entries: SignedEntry[];
  signer: Buffer;
  commitmentKey?: Buffer;
  sources: Map<string, string>;
  binary?: Buffer;
  ruleset?: Buffer;
}

class FixtureError extends Error {}

function object(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    value instanceof RawNumber
  ) {
    throw new FixtureError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new FixtureError(`${label}: unknown field ${key}`);
  }
  for (const key of keys) {
    if (!(key in value)) throw new FixtureError(`${label}: missing required field ${key}`);
  }
}

function knownKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new FixtureError(`${label}: unknown field ${key}`);
  }
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string") throw new FixtureError(`${label} must be a string`);
  return value;
}

function optionalString(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  return string(value, label);
}

function bool(value: unknown, label: string, fallback = false): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new FixtureError(`${label} must be a boolean`);
  return value;
}

function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new FixtureError(`${label} must be an array`);
  return value;
}

function uint(value: unknown, label: string, max = BigInt(Number.MAX_SAFE_INTEGER)): bigint {
  if (!(value instanceof RawNumber) || !/^(?:0|[1-9][0-9]*)$/u.test(value.literal)) {
    throw new FixtureError(`${label} must be an unsigned integer`);
  }
  const parsed = BigInt(value.literal);
  if (parsed > max) throw new FixtureError(`${label} is out of range`);
  return parsed;
}

function numberValue(value: unknown, label: string, max: number): number {
  return Number(uint(value, label, BigInt(max)));
}

function utf8(bytes: Buffer, label: string): string {
  const decoded = new TextDecoder("utf-8", { fatal: true });
  try {
    return decoded.decode(bytes);
  } catch {
    throw new FixtureError(`${label}: invalid UTF-8`);
  }
}

function b64(value: unknown, label: string): Buffer {
  const encoded = string(value, label);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)) {
    throw new FixtureError(`${label} must be canonical base64`);
  }
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded)
    throw new FixtureError(`${label} must be canonical base64`);
  return decoded;
}

function hex(value: unknown, label: string, length: number): Buffer {
  const encoded = string(value, label);
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`, "u").test(encoded)) {
    throw new FixtureError(`${label} must be ${length}-byte lowercase hex`);
  }
  return Buffer.from(encoded, "hex");
}

function digest(value: string, prefix: string, label: string): void {
  if (!new RegExp(`^${prefix}[0-9a-f]{64}$`, "u").test(value)) {
    throw new FixtureError(`${label} must be ${prefix}<64 lowercase hex>`);
  }
}

function parseOperation(value: unknown, index: number): Operation {
  const op = object(value, `recipe.operations[${index}]`);
  const allowed = new Set([
    "kind",
    "component",
    "selector",
    "occurrence",
    "passes",
    "profile",
    "decode_padding",
  ]);
  for (const key of Object.keys(op))
    if (!allowed.has(key)) throw new FixtureError(`recipe operation: unknown field ${key}`);
  return {
    kind: string(op.kind, "recipe operation.kind"),
    component: optionalString(op.component, "recipe operation.component") ?? "",
    selector: optionalString(op.selector, "recipe operation.selector") ?? "",
    occurrence:
      op.occurrence === undefined
        ? 0
        : numberValue(op.occurrence, "recipe operation.occurrence", 0xffffffff),
    passes: op.passes === undefined ? 0 : numberValue(op.passes, "recipe operation.passes", 255),
    profile: optionalString(op.profile, "recipe operation.profile") ?? "",
    decode_padding: bool(op.decode_padding, "recipe operation.decode_padding"),
  };
}

function parseProof(value: unknown): Proof {
  const raw = object(value, "proof");
  exactKeys(raw, ["version", "transform_profile_digest", "sources", "producer"], "proof");
  const sourceValues = array(raw.sources, "proof.sources");
  const sources = sourceValues.map((item, sourceIndex) => {
    const source = object(item, `proof.sources[${sourceIndex}]`);
    exactKeys(
      source,
      ["source_ordinal", "source_id", "recipe", "view_commitment", "matches"],
      "proof source",
    );
    const recipe = object(source.recipe, "source recipe");
    exactKeys(recipe, ["transform_profile_digest", "operations"], "source recipe");
    const matches = array(source.matches, "source matches").map((matchValue, matchIndex) => {
      const match = object(matchValue, `source match ${matchIndex}`);
      exactKeys(
        match,
        ["match_ordinal", "byte_start", "byte_end", "match_class", "match_commitment"],
        "source match",
      );
      return {
        match_ordinal: uint(match.match_ordinal, "match ordinal", (1n << 64n) - 1n),
        byte_start: uint(match.byte_start, "byte start", (1n << 64n) - 1n),
        byte_end: uint(match.byte_end, "byte end", (1n << 64n) - 1n),
        match_class: string(match.match_class, "match class"),
        match_commitment: string(match.match_commitment, "match commitment"),
      };
    });
    return {
      source_ordinal: uint(source.source_ordinal, "source ordinal", (1n << 64n) - 1n),
      source_id: string(source.source_id, "source ID"),
      recipe: {
        transform_profile_digest: string(
          recipe.transform_profile_digest,
          "recipe transform profile digest",
        ),
        operations: array(recipe.operations, "recipe.operations").map(parseOperation),
      },
      view_commitment: string(source.view_commitment, "view commitment"),
      matches,
    };
  });
  const producerRaw = object(raw.producer, "proof.producer");
  const allowedProducer = new Set(["binary_digest", "ruleset_digest"]);
  for (const key of Object.keys(producerRaw))
    if (!allowedProducer.has(key)) throw new FixtureError(`proof.producer: unknown field ${key}`);
  return {
    version: string(raw.version, "proof.version"),
    transform_profile_digest: string(
      raw.transform_profile_digest,
      "proof.transform_profile_digest",
    ),
    sources,
    producer: {
      binary_digest: optionalString(producerRaw.binary_digest, "proof.producer.binary_digest"),
      ruleset_digest: optionalString(producerRaw.ruleset_digest, "proof.producer.ruleset_digest"),
    },
  };
}

function parseFixture(data: string): Fixture {
  const root = object(parseJSONStrict(data), "fixture");
  exactKeys(root, ["format", "entries", "verification"], "fixture");
  if (string(root.format, "format") !== provenanceFixtureFormat)
    throw new FixtureError("unsupported fixture format");
  const verification = object(root.verification, "verification");
  const verificationAllowed = new Set([
    "signer_public_key_hex",
    "commitment_key_hex",
    "sources",
    "binary_b64",
    "ruleset_b64",
  ]);
  for (const key of Object.keys(verification))
    if (!verificationAllowed.has(key)) throw new FixtureError(`verification: unknown field ${key}`);
  const signer = hex(verification.signer_public_key_hex, "verification.signer_public_key_hex", 32);
  const commitmentHex = optionalString(
    verification.commitment_key_hex,
    "verification.commitment_key_hex",
  );
  const commitmentKey =
    commitmentHex === undefined
      ? undefined
      : hex(commitmentHex, "verification.commitment_key_hex", 32);
  const sources = new Map<string, string>();
  for (const value of array(verification.sources ?? [], "verification.sources")) {
    const source = object(value, "verification source");
    exactKeys(source, ["source_id", "bytes_b64"], "verification source");
    const id = string(source.source_id, "verification source_id");
    if (sources.has(id)) throw new FixtureError(`duplicate verification source ${id}`);
    sources.set(
      id,
      utf8(b64(source.bytes_b64, "verification source bytes_b64"), "verification source bytes"),
    );
  }
  const entries = array(root.entries, "entries").map((value, index) => {
    const entry = object(value, `entries[${index}]`);
    exactKeys(entry, ["signed_b64", "signature"], "entry");
    const bytes = b64(entry.signed_b64, "entry.signed_b64");
    const signed = object(parseJSONStrict(utf8(bytes, "signed_b64")), "signed");
    knownKeys(signed, ["chain_seq", "chain_prev_hash", "critical_features", "proof"], "signed");
    for (const key of ["chain_seq", "chain_prev_hash", "proof"]) {
      if (!(key in signed)) throw new FixtureError(`signed: missing required field ${key}`);
    }
    const signature = string(entry.signature, "entry.signature");
    if (!signature.startsWith("ed25519:"))
      throw new FixtureError("entry.signature must use ed25519 prefix");
    return {
      bytes,
      signature: hex(signature.slice("ed25519:".length), "entry.signature", 64),
      chain_seq: uint(signed.chain_seq, "signed.chain_seq", (1n << 64n) - 1n),
      chain_prev_hash: string(signed.chain_prev_hash, "signed.chain_prev_hash"),
      critical_features: array(signed.critical_features ?? [], "signed.critical_features").map(
        (feature, i) => string(feature, `signed.critical_features[${i}]`),
      ),
      proof: parseProof(signed.proof),
    };
  });
  if (entries.length === 0) throw new FixtureError("entries must not be empty");
  return {
    entries,
    signer,
    commitmentKey,
    sources,
    binary:
      verification.binary_b64 === undefined
        ? undefined
        : b64(verification.binary_b64, "verification.binary_b64"),
    ruleset:
      verification.ruleset_b64 === undefined
        ? undefined
        : b64(verification.ruleset_b64, "verification.ruleset_b64"),
  };
}

function stage(failure?: FailureStage): ProvenanceReport {
  return {
    signature: failure === "signature" ? "invalid" : "not_checked",
    chain: "not_checked",
    artifacts: "attested_unchecked",
    source_commitment: "not_checked",
    view_reproduction: "not_checked",
    location: "not_checked",
    match_commitment: "not_checked",
    overall: "invalid",
    ...(failure === undefined ? {} : { failure_stage: failure }),
  };
}

function invalid(failure: FailureStage, report: ProvenanceReport): ProvenanceReport {
  report.overall = "invalid";
  report.failure_stage = failure;
  return report;
}

function validateProofStructure(proof: Proof): void {
  if (proof.version !== proofVersion || proof.transform_profile_digest !== profileDigest) {
    throw new FixtureError("unsupported evidence provenance proof");
  }
  for (const value of [proof.producer.binary_digest, proof.producer.ruleset_digest]) {
    if (value !== undefined) digest(value, "sha256:", "producer digest");
  }
  let previousSource = -1n;
  const sourceIDs = new Set<string>();
  const sourceOrdinals = new Set<bigint>();
  for (const source of proof.sources) {
    if (
      source.source_id === "" ||
      sourceIDs.has(source.source_id) ||
      sourceOrdinals.has(source.source_ordinal)
    ) {
      throw new FixtureError("duplicate or missing source identity");
    }
    if (source.source_ordinal <= previousSource)
      throw new FixtureError("source ordinals must be strictly increasing");
    sourceIDs.add(source.source_id);
    sourceOrdinals.add(source.source_ordinal);
    previousSource = source.source_ordinal;
    validateRecipe(source.recipe);
    digest(source.view_commitment, "hmac-sha256:", "view commitment");
    let previousOrdinal = -1n;
    let previousStart = -1n;
    let previousEnd = -1n;
    for (const match of source.matches) {
      if (match.byte_end <= match.byte_start || match.match_ordinal <= previousOrdinal) {
        throw new FixtureError("invalid match interval or ordinal");
      }
      if (
        match.byte_start < previousStart ||
        match.byte_start === previousStart ||
        match.byte_start < previousEnd
      ) {
        throw new FixtureError("matches must be ordered and non-overlapping");
      }
      if (match.match_class === "") throw new FixtureError("match class is required");
      digest(match.match_commitment, "hmac-sha256:", "match commitment");
      previousOrdinal = match.match_ordinal;
      previousStart = match.byte_start;
      previousEnd = match.byte_end;
    }
  }
}

function validateRecipe(recipe: Source["recipe"]): void {
  if (recipe.transform_profile_digest !== profileDigest)
    throw new FixtureError("unknown transform profile");
  for (const op of recipe.operations) {
    if (/\p{Cc}/u.test(op.selector) || /\p{Cc}/u.test(op.profile))
      throw new FixtureError("recipe control character");
    const noParams = (): boolean =>
      op.component === "" &&
      op.selector === "" &&
      op.occurrence === 0 &&
      op.passes === 0 &&
      op.profile === "" &&
      !op.decode_padding;
    switch (op.kind) {
      case "identity":
      case "lowercase":
      case "invisible_strip":
      case "leetspeak":
      case "vowel_fold":
      case "hex_decode":
        if (!noParams()) throw new FixtureError(`unsupported parameter for ${op.kind}`);
        break;
      case "url_component":
        if (op.passes !== 0 || op.profile !== "" || op.decode_padding)
          throw new FixtureError("unsupported url_component parameter");
        if (["url", "hostname", "path"].includes(op.component)) {
          if (op.selector !== "" || op.occurrence !== 0)
            throw new FixtureError("unsupported URL component selector");
        } else if (["query_key", "query_value"].includes(op.component)) {
          if (op.selector === "") throw new FixtureError("query component: missing selector");
        } else throw new FixtureError("unknown URL component");
        break;
      case "percent_decode":
        if (
          op.passes < 1 ||
          op.passes > 4 ||
          op.component !== "" ||
          op.selector !== "" ||
          op.occurrence !== 0 ||
          op.profile !== "" ||
          op.decode_padding
        ) {
          throw new FixtureError("invalid percent_decode parameters");
        }
        break;
      case "dlp_normalize":
        if (
          op.profile !== "pipelock-dlp-v1" ||
          op.component !== "" ||
          op.selector !== "" ||
          op.occurrence !== 0 ||
          op.passes !== 0 ||
          op.decode_padding
        ) {
          throw new FixtureError("invalid dlp_normalize parameters");
        }
        break;
      case "base32_decode":
      case "base64_decode":
        if (
          op.component !== "" ||
          op.selector !== "" ||
          op.occurrence !== 0 ||
          op.passes !== 0 ||
          op.profile !== ""
        ) {
          throw new FixtureError(`invalid ${op.kind} parameters`);
        }
        break;
      default:
        throw new FixtureError(`unknown operation ${op.kind}`);
    }
  }
}

function frame(value: Buffer): Buffer {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(value.length));
  return Buffer.concat([length, value]);
}

function u64(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(value);
  return out;
}

function u32(value: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function operationBytes(op: Operation): Buffer {
  const kind: Record<string, number> = {
    identity: 1,
    url_component: 2,
    percent_decode: 3,
    dlp_normalize: 4,
    lowercase: 5,
    invisible_strip: 6,
    hex_decode: 7,
    base32_decode: 8,
    base64_decode: 9,
    leetspeak: 10,
    vowel_fold: 11,
  };
  const component: Record<string, number> = {
    "": 0,
    url: 1,
    hostname: 2,
    path: 3,
    query_key: 4,
    query_value: 5,
  };
  return Buffer.concat([
    frame(Buffer.from([kind[op.kind] ?? 0])),
    frame(Buffer.from([component[op.component] ?? 0])),
    frame(Buffer.from(op.selector, "utf8")),
    frame(u32(op.occurrence)),
    frame(Buffer.from([op.passes])),
    frame(Buffer.from(op.profile, "utf8")),
    frame(Buffer.from([op.decode_padding ? 1 : 0])),
  ]);
}

function recipeBytes(recipe: Source["recipe"]): Buffer {
  return Buffer.concat([
    frame(Buffer.from("pipelock/evidence-provenance/recipe/v1", "ascii")),
    frame(Buffer.from(recipe.transform_profile_digest, "ascii")),
    frame(u64(BigInt(recipe.operations.length))),
    ...recipe.operations.map((op) => frame(operationBytes(op))),
  ]);
}

function commitment(key: Buffer, domain: string, values: Buffer[]): string {
  const mac = createHmac("sha256", key);
  mac.update(frame(Buffer.from(domain, "ascii")));
  for (const value of values) mac.update(frame(value));
  return `hmac-sha256:${mac.digest("hex")}`;
}

function commitView(key: Buffer, source: Source, view: string): string {
  return commitment(key, "pipelock/evidence-provenance/view/v1", [
    u64(source.source_ordinal),
    Buffer.from(source.source_id, "utf8"),
    Buffer.from(source.recipe.transform_profile_digest, "ascii"),
    recipeBytes(source.recipe),
    Buffer.from(view, "utf8"),
  ]);
}

function commitMatch(key: Buffer, source: Source, match: Match): string {
  return commitment(key, "pipelock/evidence-provenance/match/v1", [
    Buffer.from(source.source_id, "utf8"),
    Buffer.from(source.recipe.transform_profile_digest, "ascii"),
    recipeBytes(source.recipe),
    Buffer.from(source.view_commitment, "ascii"),
    u64(match.match_ordinal),
    u64(match.byte_start),
    u64(match.byte_end),
    Buffer.from(match.match_class, "utf8"),
  ]);
}

function decodePercent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new FixtureError("percent decode failed");
  }
}

function queryValues(raw: string, selector: string): string[] {
  const values: string[] = [];
  for (const part of raw === "" ? [] : raw.split("&")) {
    const equals = part.indexOf("=");
    const rawKey = equals < 0 ? part : part.slice(0, equals);
    const rawValue = equals < 0 ? "" : part.slice(equals + 1);
    let key: string;
    let value: string;
    try {
      key = decodeURIComponent(rawKey.replaceAll("+", " "));
      value = decodeURIComponent(rawValue.replaceAll("+", " "));
    } catch {
      throw new FixtureError("query parse failed");
    }
    if (key === selector) values.push(value);
  }
  return values;
}

function selectURLComponent(value: string, op: Operation): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new FixtureError("URL parse: invalid absolute URL");
  }
  switch (op.component) {
    case "url":
      return value;
    case "hostname":
      return parsed.hostname;
    case "path":
      return parsed.pathname;
    case "query_key":
      if (queryValues(parsed.search.slice(1), op.selector)[op.occurrence] === undefined) {
        throw new FixtureError(`query component: occurrence ${op.occurrence} unavailable`);
      }
      return op.selector;
    case "query_value": {
      const valueAt = queryValues(parsed.search.slice(1), op.selector)[op.occurrence];
      if (valueAt === undefined)
        throw new FixtureError(`query component: occurrence ${op.occurrence} unavailable`);
      return valueAt;
    }
    default:
      throw new FixtureError("unknown URL component");
  }
}

function invisibleStrip(value: string): string {
  return Array.from(value)
    .filter((ch) => {
      const point = ch.codePointAt(0) ?? 0;
      if (
        (point <= 0x1f && point !== 9 && point !== 10 && point !== 13) ||
        point === 0x7f ||
        (point >= 0x80 && point <= 0x9f)
      )
        return false;
      return !(
        point === 0xad ||
        (point >= 0x115f && point <= 0x1160) ||
        (point >= 0x200b && point <= 0x200f) ||
        (point >= 0x202a && point <= 0x202e) ||
        (point >= 0x2060 && point <= 0x2064) ||
        (point >= 0x2066 && point <= 0x2069) ||
        point === 0x3164 ||
        (point >= 0xfe00 && point <= 0xfe0f) ||
        point === 0xfeff ||
        (point >= 0xfff9 && point <= 0xfffb) ||
        (point >= 0xe0000 && point <= 0xe007f) ||
        (point >= 0xe0100 && point <= 0xe01ef)
      );
    })
    .join("");
}

function dlpNormalize(value: string): string {
  const stripped = invisibleStrip(value).replace(/[\u0009\u000a\u000d]/gu, "");
  const noExoticSpace = stripped.replace(
    /[\u00a0\u1680\u180e\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/gu,
    "",
  );
  const confusables: Record<string, string> = {
    а: "a",
    е: "e",
    о: "o",
    р: "p",
    с: "c",
    х: "x",
    Α: "A",
    Β: "B",
    Ε: "E",
    Ι: "I",
    Κ: "K",
    Μ: "M",
    Ν: "N",
    Ο: "O",
    Ρ: "P",
    Τ: "T",
    Χ: "X",
    ο: "o",
    α: "a",
    і: "i",
    Ø: "O",
    ø: "o",
    Ł: "L",
    ł: "l",
  };
  return Array.from(noExoticSpace.normalize("NFKC"), (ch) => confusables[ch] ?? ch)
    .join("")
    .normalize("NFD")
    .replace(/\p{Mn}/gu, "");
}

function base32Decode(value: string, padded: boolean): Buffer {
  if (!/^[A-Z2-7]*={0,6}$/u.test(value) || (!padded && value.includes("=")))
    throw new FixtureError("base32 decode failed");
  const unpadded = value.replace(/=+$/u, "");
  let bits = "";
  for (const ch of unpadded)
    bits += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8)
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  const decoded = Buffer.from(bytes);
  const encoded = base32Encode(decoded, padded);
  if (encoded !== value) throw new FixtureError("base32 decode: non-canonical encoding");
  return decoded;
}

function base32Encode(bytes: Buffer, padded: boolean): string {
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  let out = "";
  for (let index = 0; index < bits.length; index += 5)
    out += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[
      Number.parseInt(bits.slice(index, index + 5).padEnd(5, "0"), 2)
    ];
  return padded ? out.padEnd(Math.ceil(out.length / 8) * 8, "=") : out;
}

function applyRecipe(recipe: Source["recipe"], input: string): string {
  if (Buffer.byteLength(input, "utf8") > maxInputBytes)
    throw new FixtureError("recipe input: exceeds profile byte limit");
  let value = input;
  for (const op of recipe.operations) {
    switch (op.kind) {
      case "identity":
        break;
      case "url_component":
        value = selectURLComponent(value, op);
        break;
      case "percent_decode":
        for (let i = 0; i < op.passes; i++) value = decodePercent(value);
        break;
      case "dlp_normalize":
        value = dlpNormalize(value);
        break;
      case "lowercase":
        value = value.toLowerCase();
        break;
      case "invisible_strip":
        value = invisibleStrip(value);
        break;
      case "hex_decode": {
        if (!/^[0-9a-f]*$/u.test(value) || value.length % 2 !== 0)
          throw new FixtureError("hex decode failed");
        const decoded = Buffer.from(value, "hex");
        if (decoded.toString("hex") !== value)
          throw new FixtureError("hex decode: non-canonical encoding");
        value = utf8(decoded, "hex decode output");
        break;
      }
      case "base32_decode":
        value = utf8(base32Decode(value, op.decode_padding), "base32 decode output");
        break;
      case "base64_decode": {
        const decoded = op.decode_padding ? b64(value, "base64 decode") : decodeRawBase64(value);
        value = utf8(decoded, "base64 decode output");
        break;
      }
      case "leetspeak":
        value = value.replace(
          /[013457@$]/gu,
          (ch) =>
            ({ "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s" })[
              ch
            ] ?? ch,
        );
        break;
      case "vowel_fold":
        value = value.replace(/[aeiou]/gu, "a").replace(/[AEIOU]/gu, "A");
        break;
      default:
        throw new FixtureError(`unknown operation ${op.kind}`);
    }
    if (Buffer.byteLength(value, "utf8") > maxOutputBytes)
      throw new FixtureError("recipe output exceeds profile byte limit");
  }
  return value;
}

function decodeRawBase64(value: string): Buffer {
  if (!/^[A-Za-z0-9+/]*$/u.test(value) || value.length % 4 === 1)
    throw new FixtureError("base64 decode failed");
  const padded = value.padEnd(Math.ceil(value.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64");
  if (decoded.toString("base64").replace(/=+$/u, "") !== value)
    throw new FixtureError("base64 decode: non-canonical encoding");
  return decoded;
}

function boundary(bytes: Buffer, offset: bigint): boolean {
  if (offset === 0n || offset === BigInt(bytes.length)) return true;
  return offset < BigInt(bytes.length) && (bytes[Number(offset)]! & 0xc0) !== 0x80;
}

function artifacts(proof: Proof, fixture: Fixture): ArtifactStage {
  const pairs: Array<[string | undefined, Buffer | undefined]> = [
    [proof.producer.binary_digest, fixture.binary],
    [proof.producer.ruleset_digest, fixture.ruleset],
  ];
  let unchecked = false;
  for (const [attested, supplied] of pairs) {
    if (attested === undefined) continue;
    if (supplied === undefined) unchecked = true;
    else if (`sha256:${createHash("sha256").update(supplied).digest("hex")}` !== attested)
      return "mismatch";
  }
  return unchecked ? "attested_unchecked" : "matched";
}

// verifyProvenanceFixture returns compact stages only. It never exposes source
// bytes, keys, or implementation errors; the stage is the comparable contract.
export async function verifyProvenanceFixture(data: string): Promise<ProvenanceReport> {
  let fixture: Fixture;
  try {
    fixture = parseFixture(data);
  } catch {
    return invalid("proof_structure", stage("proof_structure"));
  }
  const report = stage();
  for (const entry of fixture.entries) {
    if (
      !(await ed25519.verifyAsync(entry.signature, entry.bytes, fixture.signer, { zip215: false }))
    )
      return invalid("signature", stage("signature"));
  }
  report.signature = "verified";
  for (let index = 0; index < fixture.entries.length; index++) {
    const entry = fixture.entries[index]!;
    const expectedPrev =
      index === 0
        ? "genesis"
        : `sha256:${createHash("sha256")
            .update(fixture.entries[index - 1]!.bytes)
            .digest("hex")}`;
    if (entry.chain_seq !== BigInt(index) || entry.chain_prev_hash !== expectedPrev) {
      report.chain = "invalid";
      return invalid("chain", report);
    }
  }
  report.chain = "verified";
  for (const entry of fixture.entries) {
    if (entry.critical_features.length !== 1 || entry.critical_features[0] !== knownFeature)
      return invalid("critical_features", report);
  }
  try {
    for (const entry of fixture.entries) validateProofStructure(entry.proof);
  } catch {
    return invalid("proof_structure", report);
  }
  let artifactsUnchecked = false;
  for (const entry of fixture.entries) {
    const artifactStage = artifacts(entry.proof, fixture);
    if (artifactStage === "mismatch") {
      report.artifacts = "mismatch";
      return invalid("artifacts", report);
    }
    artifactsUnchecked ||= artifactStage === "attested_unchecked";
  }
  report.artifacts = artifactsUnchecked ? "attested_unchecked" : "matched";
  const allSources: Array<{ source: Source; raw?: string; view?: string }> = [];
  for (const entry of fixture.entries) {
    for (const source of entry.proof.sources)
      allSources.push({ source, raw: fixture.sources.get(source.source_id) });
  }
  if (allSources.some((item) => item.raw === undefined)) {
    report.view_reproduction = "not_checked";
    report.location = "not_checked";
    report.match_commitment = "not_checked";
    report.overall = "incomplete";
    return report;
  }
  try {
    for (const item of allSources) item.view = applyRecipe(item.source.recipe, item.raw!);
  } catch {
    report.view_reproduction = "mismatch";
    return invalid("view_reproduction", report);
  }
  report.view_reproduction = "reproduced";
  for (const item of allSources) {
    const bytes = Buffer.from(item.view!, "utf8");
    for (const match of item.source.matches) {
      if (
        match.byte_end > BigInt(bytes.length) ||
        !boundary(bytes, match.byte_start) ||
        !boundary(bytes, match.byte_end)
      ) {
        report.location = "mismatch";
        return invalid("location", report);
      }
    }
  }
  report.location = "exact_coordinates";
  if (fixture.commitmentKey === undefined) {
    report.match_commitment = "not_checked";
    report.overall = "incomplete";
    return report;
  }
  for (const item of allSources) {
    if (
      commitView(fixture.commitmentKey, item.source, item.view!) !== item.source.view_commitment
    ) {
      report.match_commitment = "mismatch";
      return invalid("view_commitment", report);
    }
    for (const match of item.source.matches) {
      if (commitMatch(fixture.commitmentKey, item.source, match) !== match.match_commitment) {
        report.match_commitment = "mismatch";
        return invalid("match_commitment", report);
      }
    }
  }
  report.match_commitment = "opened";
  // PR3 contains no source-commitment field. Its explicit unavailable state is
  // load-bearing: it prevents fixture support from being misreported as a fully
  // opened provenance proof.
  report.source_commitment = "not_checked";
  report.overall = "incomplete";
  return report;
}

export async function runProvenanceFixture(path: string): Promise<ProvenanceReport> {
  try {
    return await verifyProvenanceFixture(readFileSync(path, "utf8"));
  } catch {
    return invalid("proof_structure", stage("proof_structure"));
  }
}

export function comparableProvenance(report: ProvenanceReport): string {
  const ordered: ProvenanceReport = {
    signature: report.signature,
    chain: report.chain,
    artifacts: report.artifacts,
    source_commitment: report.source_commitment,
    view_reproduction: report.view_reproduction,
    location: report.location,
    match_commitment: report.match_commitment,
    overall: report.overall,
    ...(report.failure_stage === undefined ? {} : { failure_stage: report.failure_stage }),
  };
  return JSON.stringify(ordered);
}
