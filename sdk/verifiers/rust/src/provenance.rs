// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//! Experimental, fixture-only evidence-provenance verifier.
//!
//! This module deliberately consumes a test fixture wrapper rather than a
//! registered receipt payload. It must not be wired into production receipt
//! emission or treated as a capability claim.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2_10::Sha256 as HmacSha256;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;
use url::Url;

use crate::util::{reject_duplicate_keys, sha256_hex, Result, VerifierError};

const FIXTURE_FORMAT: &str = "pipelock-evidence-provenance-verification-fixture/v1";
const PROOF_VERSION: &str = "pipelock-evidence-provenance-proof/v1";
const PROFILE_DIGEST: &str =
    "sha256:8bc27d5d89e4e5ba3e0d1e68a25a3f0170f9a5ea2f19edf81a9a90bf82e23b3e";
const GENESIS: &str = "genesis";
const TRUST_ROOTS: &str = "fixture supplied; self-attested; not authenticated";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProvenanceReport {
    pub trust_roots: String,
    pub authenticated_provenance: bool,
    pub signature: String,
    pub chain: String,
    pub artifacts: String,
    pub source_commitment: String,
    pub view_reproduction: String,
    pub location: String,
    pub match_commitment: String,
    pub overall: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<String>,
}

impl ProvenanceReport {
    fn pending() -> Self {
        Self {
            trust_roots: TRUST_ROOTS.into(),
            authenticated_provenance: false,
            signature: "not_checked".into(),
            chain: "not_checked".into(),
            artifacts: "attested_unchecked".into(),
            source_commitment: "not_checked".into(),
            view_reproduction: "not_checked".into(),
            location: "not_checked".into(),
            match_commitment: "not_checked".into(),
            overall: "incomplete".into(),
            failure_stage: None,
        }
    }

    fn fail(&mut self, stage: &str) {
        self.overall = "invalid".into();
        self.failure_stage = Some(stage.into());
    }

    fn proof_structure_failure() -> Self {
        let mut report = Self::pending();
        report.fail("proof_structure");
        report
    }
}

#[derive(Clone)]
struct SignedEntry {
    bytes: Vec<u8>,
    value: Value,
}

#[derive(Clone)]
struct VerificationInput {
    signer: Vec<u8>,
    commitment_key: Option<Vec<u8>>,
    sources: BTreeMap<String, String>,
    binary: Option<Vec<u8>>,
    ruleset: Option<Vec<u8>>,
}

pub fn run_provenance(path: &Path) -> Result<ProvenanceReport> {
    let bytes = fs::read(path)
        .map_err(|err| VerifierError::Runtime(format!("read {}: {err}", path.display())))?;
    Ok(
        verify_fixture_bytes(&bytes)
            .unwrap_or_else(|_| ProvenanceReport::proof_structure_failure()),
    )
}

/// Verify one fixture. Errors here indicate a malformed fixture envelope;
/// authenticated proof failures are represented in [`ProvenanceReport`].
pub fn verify_fixture_bytes(bytes: &[u8]) -> std::result::Result<ProvenanceReport, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "fixture: invalid UTF-8".to_string())?;
    reject_duplicate_keys(text).map_err(|err| err.to_string())?;
    let value: Value = serde_json::from_str(text).map_err(|err| format!("fixture JSON: {err}"))?;
    let object = object(&value, "fixture")?;
    exact_keys(object, &["format", "entries", "verification"], "fixture")?;
    if string(object, "format", "fixture")? != FIXTURE_FORMAT {
        return Err("fixture: unsupported format".into());
    }
    let verification = parse_verification(required(object, "verification", "fixture")?)?;
    let entries = array(required(object, "entries", "fixture")?, "fixture.entries")?;
    if entries.is_empty() {
        return Err("fixture.entries: must not be empty".into());
    }
    let parsed = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| parse_entry(entry, index))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    verify_entries(&parsed, &verification)
}

fn parse_entry(value: &Value, index: usize) -> std::result::Result<SignedEntry, String> {
    let entry = object(value, &format!("fixture.entries[{index}]"))?;
    exact_keys(entry, &["signed_b64", "signature"], "fixture entry")?;
    let bytes = decode_b64(string(entry, "signed_b64", "fixture entry")?, "signed_b64")?;
    let signed_text =
        std::str::from_utf8(&bytes).map_err(|_| "signed_b64: invalid UTF-8".to_string())?;
    reject_duplicate_keys(signed_text).map_err(|err| format!("signed JSON: {err}"))?;
    let signed: Value =
        serde_json::from_str(signed_text).map_err(|err| format!("signed JSON: {err}"))?;
    let signature = string(entry, "signature", "fixture entry")?;
    if !signature.starts_with("ed25519:") {
        return Err("fixture entry: signature must use ed25519:".into());
    }
    // Retain the detached signature in the object so verification stays exact
    // while avoiding a second public wrapper type.
    let mut value = signed;
    value
        .as_object_mut()
        .ok_or_else(|| "signed JSON: must be an object".to_string())?
        .insert(
            "__fixture_signature".into(),
            Value::String(signature[8..].into()),
        );
    Ok(SignedEntry { bytes, value })
}

fn parse_verification(value: &Value) -> std::result::Result<VerificationInput, String> {
    let verification = object(value, "verification")?;
    exact_keys_with_optional(
        verification,
        &[
            "signer_public_key_hex",
            "commitment_key_hex",
            "sources",
            "binary_b64",
            "ruleset_b64",
        ],
        &["commitment_key_hex", "sources", "binary_b64", "ruleset_b64"],
        "verification",
    )?;
    let signer = decode_hex(
        string(verification, "signer_public_key_hex", "verification")?,
        32,
        "signer_public_key_hex",
    )?;
    let commitment_key = optional_string(verification, "commitment_key_hex")?
        .map(|value| decode_hex(value, 0, "commitment_key_hex"))
        .transpose()?;
    if let Some(key) = &commitment_key {
        if key.len() < 32 {
            return Err("commitment_key_hex: must encode at least 32 bytes".into());
        }
    }
    let sources_array: &[Value] = match verification.get("sources") {
        Some(value) => array(value, "verification.sources")?,
        None => &[],
    };
    let mut sources = BTreeMap::new();
    for (index, source) in sources_array.iter().enumerate() {
        let source = object(source, "verification source")?;
        exact_keys(source, &["source_id", "bytes_b64"], "verification source")?;
        let id = string(source, "source_id", "verification source")?.to_string();
        let bytes = decode_b64(
            string(source, "bytes_b64", "verification source")?,
            "source bytes",
        )?;
        let text =
            String::from_utf8(bytes).map_err(|_| "source bytes: invalid UTF-8".to_string())?;
        if sources.insert(id.clone(), text).is_some() {
            return Err(format!(
                "verification.sources[{index}]: duplicate source_id {id:?}"
            ));
        }
    }
    Ok(VerificationInput {
        signer,
        commitment_key,
        sources,
        binary: optional_string(verification, "binary_b64")?
            .map(|v| decode_b64(v, "binary_b64"))
            .transpose()?,
        ruleset: optional_string(verification, "ruleset_b64")?
            .map(|v| decode_b64(v, "ruleset_b64"))
            .transpose()?,
    })
}

fn verify_entries(
    entries: &[SignedEntry],
    input: &VerificationInput,
) -> std::result::Result<ProvenanceReport, String> {
    let mut report = ProvenanceReport::pending();
    let verifying: [u8; 32] = input
        .signer
        .as_slice()
        .try_into()
        .map_err(|_| "signer key length".to_string())?;
    let verifying =
        VerifyingKey::from_bytes(&verifying).map_err(|err| format!("signer key: {err}"))?;
    let mut missing_source = false;
    for entry in entries {
        let signature_hex = entry
            .value
            .get("__fixture_signature")
            .and_then(Value::as_str)
            .ok_or_else(|| "fixture signature missing".to_string())?;
        let signature = decode_hex(signature_hex, 64, "signature")?;
        let signature =
            Signature::from_slice(&signature).map_err(|err| format!("signature: {err}"))?;
        if verifying.verify_strict(&entry.bytes, &signature).is_err() {
            report.signature = "invalid".into();
            report.fail("signature");
            return Ok(report);
        }
    }
    report.signature = "verified".into();

    let mut previous: Option<&SignedEntry> = None;
    for (index, entry) in entries.iter().enumerate() {
        let expected_previous = previous
            .map(|prior| format!("sha256:{}", sha256_hex(&prior.bytes)))
            .unwrap_or_else(|| GENESIS.into());
        if !chain_fields_match(entry, index as u64, &expected_previous) {
            report.chain = "invalid".into();
            report.fail("chain");
            return Ok(report);
        }
        previous = Some(entry);
    }
    report.chain = "verified".into();

    for entry in entries {
        let signed = match signed_object(entry) {
            Ok(signed) => signed,
            Err(_) => {
                report.fail("proof_structure");
                return Ok(report);
            }
        };
        if !critical_features_ok(signed) {
            report.fail("critical_features");
            return Ok(report);
        }
        let proof_value = match required(signed, "proof", "signed") {
            Ok(proof) => proof,
            Err(_) => {
                report.fail("proof_structure");
                return Ok(report);
            }
        };
        let proof = match parse_proof(proof_value) {
            Ok(proof) => proof,
            Err(_) => {
                report.fail("proof_structure");
                return Ok(report);
            }
        };
        match verify_artifacts(&proof, input) {
            Stage::Matched => report.artifacts = "matched".into(),
            Stage::Unchecked => report.artifacts = "attested_unchecked".into(),
            Stage::Mismatch => {
                report.artifacts = "mismatch".into();
                report.fail("artifacts");
                return Ok(report);
            }
        }
        for source in &proof.sources {
            let Some(raw) = input.sources.get(&source.source_id) else {
                missing_source = true;
                report.view_reproduction = "not_checked".into();
                report.location = "not_checked".into();
                report.match_commitment = "not_checked".into();
                report.overall = "incomplete".into();
                continue;
            };
            let view = match apply_recipe(raw, &source.recipe) {
                Ok(view) => view,
                Err(_) => {
                    report.view_reproduction = "mismatch".into();
                    report.fail("view_reproduction");
                    return Ok(report);
                }
            };
            report.view_reproduction = "reproduced".into();
            for matched in &source.matches {
                if !byte_interval_valid(&view, matched.start, matched.end) {
                    report.location = "mismatch".into();
                    report.fail("location");
                    return Ok(report);
                }
                report.location = "exact_coordinates".into();
                let Some(key) = input.commitment_key.as_deref() else {
                    report.match_commitment = "not_checked".into();
                    continue;
                };
                let expected_view = commitment(
                    key,
                    "pipelock/evidence-provenance/view/v1",
                    &[
                        u64_bytes(source.source_ordinal),
                        source.source_id.as_bytes().to_vec(),
                        source.recipe.profile.as_bytes().to_vec(),
                        recipe_bytes(&source.recipe)?,
                        view.as_bytes().to_vec(),
                    ],
                );
                if expected_view != source.view_commitment {
                    // Reproduction means the typed recipe ran and coordinates
                    // address that view. A view HMAC is a separate opening
                    // claim, so do not misreport this as failed reproduction.
                    if missing_source {
                        // Aggregate stages are only positive when every
                        // source can be reproduced. Still surface the later
                        // HMAC failure so a missing sibling cannot mask it.
                        report.view_reproduction = "not_checked".into();
                        report.location = "not_checked".into();
                    }
                    report.match_commitment = "mismatch".into();
                    report.fail("view_commitment");
                    return Ok(report);
                }
                let expected = commitment(
                    key,
                    "pipelock/evidence-provenance/match/v1",
                    &[
                        source.source_id.as_bytes().to_vec(),
                        source.recipe.profile.as_bytes().to_vec(),
                        recipe_bytes(&source.recipe)?,
                        source.view_commitment.as_bytes().to_vec(),
                        u64_bytes(matched.ordinal),
                        u64_bytes(matched.start),
                        u64_bytes(matched.end),
                        matched.class.as_bytes().to_vec(),
                    ],
                );
                if expected != matched.commitment {
                    report.match_commitment = "mismatch".into();
                    report.fail("match_commitment");
                    return Ok(report);
                }
                report.match_commitment = "opened".into();
            }
        }
    }
    if missing_source {
        report.view_reproduction = "not_checked".into();
        report.location = "not_checked".into();
        report.match_commitment = "not_checked".into();
    }
    // PR3 has no source commitment, so authenticated proof opening remains
    // incomplete by design until that future field exists.
    report.overall = "incomplete".into();
    Ok(report)
}

fn chain_fields_match(
    entry: &SignedEntry,
    expected_sequence: u64,
    expected_previous: &str,
) -> bool {
    let Ok(signed) = object(&entry.value, "signed") else {
        return false;
    };
    matches!(
        (signed.get("chain_seq").and_then(Value::as_u64), signed.get("chain_prev_hash").and_then(Value::as_str)),
        (Some(sequence), Some(previous)) if sequence == expected_sequence && previous == expected_previous
    )
}

fn signed_object(entry: &SignedEntry) -> std::result::Result<&Map<String, Value>, String> {
    let object = object(&entry.value, "signed")?;
    let mut allowed = HashSet::from([
        "chain_seq",
        "chain_prev_hash",
        "critical_features",
        "proof",
        "__fixture_signature",
    ]);
    if object.keys().any(|key| !allowed.remove(key.as_str())) || !allowed.is_empty() {
        return Err("signed: unknown or missing field".into());
    }
    Ok(object)
}

fn critical_features_ok(signed: &Map<String, Value>) -> bool {
    let Some(features) = signed.get("critical_features").and_then(Value::as_array) else {
        return false;
    };
    features.len() == 1 && features[0].as_str() == Some("evidence_provenance")
}

#[derive(Clone)]
struct Proof {
    producer: Producer,
    sources: Vec<ProofSource>,
}
#[derive(Clone)]
struct Producer {
    binary: Option<String>,
    ruleset: Option<String>,
}
#[derive(Clone)]
struct ProofSource {
    source_ordinal: u64,
    source_id: String,
    recipe: Recipe,
    view_commitment: String,
    matches: Vec<ProofMatch>,
}
#[derive(Clone)]
struct ProofMatch {
    ordinal: u64,
    start: u64,
    end: u64,
    class: String,
    commitment: String,
}
#[derive(Clone)]
struct Recipe {
    profile: String,
    operations: Vec<Operation>,
}
#[derive(Clone)]
struct Operation {
    kind: String,
    component: String,
    selector: String,
    occurrence: u32,
    passes: u8,
    profile: String,
    padding: bool,
}

fn parse_proof(value: &Value) -> std::result::Result<Proof, String> {
    let proof = object(value, "proof")?;
    exact_keys(
        proof,
        &["version", "transform_profile_digest", "sources", "producer"],
        "proof",
    )?;
    if string(proof, "version", "proof")? != PROOF_VERSION
        || string(proof, "transform_profile_digest", "proof")? != PROFILE_DIGEST
    {
        return Err("proof: unsupported version or profile".into());
    }
    let producer_value = object(required(proof, "producer", "proof")?, "proof.producer")?;
    exact_keys_with_optional(
        producer_value,
        &["binary_digest", "ruleset_digest"],
        &["binary_digest", "ruleset_digest"],
        "producer",
    )?;
    let producer = Producer {
        binary: optional_string(producer_value, "binary_digest")?.map(str::to_string),
        ruleset: optional_string(producer_value, "ruleset_digest")?.map(str::to_string),
    };
    for digest in [producer.binary.as_deref(), producer.ruleset.as_deref()]
        .into_iter()
        .flatten()
    {
        valid_digest(digest, "sha256:")?;
    }
    let mut prior_source = None;
    let mut ids = HashSet::new();
    let mut sources = Vec::new();
    for value in array(required(proof, "sources", "proof")?, "proof.sources")? {
        let source = object(value, "proof source")?;
        exact_keys(
            source,
            &[
                "source_ordinal",
                "source_id",
                "recipe",
                "view_commitment",
                "matches",
            ],
            "proof source",
        )?;
        let ordinal = u64_value(source, "source_ordinal", "proof source")?;
        let id = string(source, "source_id", "proof source")?.to_string();
        if id.is_empty()
            || !ids.insert(id.clone())
            || prior_source.is_some_and(|prior| ordinal <= prior)
        {
            return Err("proof source: duplicate or unordered identity".into());
        }
        prior_source = Some(ordinal);
        let recipe = parse_recipe(required(source, "recipe", "proof source")?)?;
        let commitment = string(source, "view_commitment", "proof source")?.to_string();
        valid_digest(&commitment, "hmac-sha256:")?;
        let mut matches = Vec::new();
        let mut prior_match = None;
        for value in array(required(source, "matches", "proof source")?, "matches")? {
            let matched = object(value, "match")?;
            exact_keys(
                matched,
                &[
                    "match_ordinal",
                    "byte_start",
                    "byte_end",
                    "match_class",
                    "match_commitment",
                ],
                "match",
            )?;
            let ordinal = u64_value(matched, "match_ordinal", "match")?;
            let start = u64_value(matched, "byte_start", "match")?;
            let end = u64_value(matched, "byte_end", "match")?;
            let class = string(matched, "match_class", "match")?.to_string();
            let commitment = string(matched, "match_commitment", "match")?.to_string();
            valid_digest(&commitment, "hmac-sha256:")?;
            if end <= start
                || prior_match.is_some_and(|(prior_ordinal, prior_start, prior_end)| {
                    ordinal <= prior_ordinal || start <= prior_start || start < prior_end
                })
            {
                return Err("match: invalid order or interval".into());
            }
            prior_match = Some((ordinal, start, end));
            matches.push(ProofMatch {
                ordinal,
                start,
                end,
                class,
                commitment,
            });
        }
        sources.push(ProofSource {
            source_ordinal: ordinal,
            source_id: id,
            recipe,
            view_commitment: commitment,
            matches,
        });
    }
    Ok(Proof { producer, sources })
}

fn parse_recipe(value: &Value) -> std::result::Result<Recipe, String> {
    let recipe = object(value, "recipe")?;
    exact_keys(
        recipe,
        &["transform_profile_digest", "operations"],
        "recipe",
    )?;
    let profile = string(recipe, "transform_profile_digest", "recipe")?.to_string();
    if profile.is_empty() {
        return Err("missing transform profile digest".into());
    }
    if profile != PROFILE_DIGEST {
        return Err("recipe: unknown transform profile".into());
    }
    let mut operations = Vec::new();
    for value in array(required(recipe, "operations", "recipe")?, "operations")? {
        let operation = object(value, "operation")?;
        let allowed = [
            "kind",
            "component",
            "selector",
            "occurrence",
            "passes",
            "profile",
            "decode_padding",
        ];
        if operation.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err("operation: unknown field".into());
        }
        let op = Operation {
            kind: string(operation, "kind", "operation")?.to_string(),
            component: optional_string(operation, "component")?
                .unwrap_or("")
                .to_string(),
            selector: optional_string(operation, "selector")?
                .unwrap_or("")
                .to_string(),
            occurrence: optional_u64(operation, "occurrence")?
                .unwrap_or(0)
                .try_into()
                .map_err(|_| "operation: occurrence out of range")?,
            passes: optional_u64(operation, "passes")?
                .unwrap_or(0)
                .try_into()
                .map_err(|_| "operation: passes out of range")?,
            profile: optional_string(operation, "profile")?
                .unwrap_or("")
                .to_string(),
            padding: operation
                .get("decode_padding")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        validate_operation(&op)?;
        operations.push(op);
    }
    Ok(Recipe {
        profile,
        operations,
    })
}

fn validate_operation(op: &Operation) -> std::result::Result<(), String> {
    if op.selector.chars().any(char::is_control) {
        return Err(format!(
            "selector for {} contains control character",
            op.kind
        ));
    }
    if op.profile.chars().any(char::is_control) {
        return Err(format!(
            "profile for {} contains control character",
            op.kind
        ));
    }
    let empty = || {
        op.component.is_empty()
            && op.selector.is_empty()
            && op.occurrence == 0
            && op.passes == 0
            && op.profile.is_empty()
            && !op.padding
    };
    match op.kind.as_str() {
        "identity" | "lowercase" | "invisible_strip" | "leetspeak" | "vowel_fold"
        | "hex_decode"
            if empty() =>
        {
            Ok(())
        }
        "url_component"
            if matches!(op.component.as_str(), "query_key" | "query_value")
                && op.selector.is_empty() =>
        {
            Err("query component: missing selector".into())
        }
        "url_component" => match op.component.as_str() {
            "url" | "hostname" | "path"
                if op.selector.is_empty()
                    && op.occurrence == 0
                    && op.passes == 0
                    && op.profile.is_empty()
                    && !op.padding =>
            {
                Ok(())
            }
            "query_key" | "query_value"
                if !op.selector.is_empty()
                    && op.passes == 0
                    && op.profile.is_empty()
                    && !op.padding =>
            {
                Ok(())
            }
            "url" | "hostname" | "path" | "query_key" | "query_value" => {
                Err("url_component: unsupported parameters".into())
            }
            _ => Err(format!("unknown URL component {:?}", op.component)),
        },
        "percent_decode" if op.passes == 0 || op.passes > 4 => {
            Err("percent decode passes must be 1..4".into())
        }
        "percent_decode"
            if (1..=4).contains(&op.passes)
                && op.component.is_empty()
                && op.selector.is_empty()
                && op.occurrence == 0
                && op.profile.is_empty()
                && !op.padding =>
        {
            Ok(())
        }
        "dlp_normalize" if op.profile != "pipelock-dlp-v1" => {
            Err(format!("unknown DLP profile {:?}", op.profile))
        }
        "dlp_normalize"
            if op.profile == "pipelock-dlp-v1"
                && op.component.is_empty()
                && op.selector.is_empty()
                && op.occurrence == 0
                && op.passes == 0
                && !op.padding =>
        {
            Ok(())
        }
        "base32_decode" | "base64_decode"
            if op.component.is_empty()
                && op.selector.is_empty()
                && op.occurrence == 0
                && op.passes == 0
                && op.profile.is_empty() =>
        {
            Ok(())
        }
        "identity" | "lowercase" | "invisible_strip" | "leetspeak" | "vowel_fold"
        | "hex_decode" | "percent_decode" | "dlp_normalize" | "base32_decode" | "base64_decode" => {
            Err(format!("unsupported parameters for {}", op.kind))
        }
        _ => Err(format!("unknown operation {:?}", op.kind)),
    }
}

enum Stage {
    Matched,
    Unchecked,
    Mismatch,
}
fn verify_artifacts(proof: &Proof, input: &VerificationInput) -> Stage {
    let checks = [
        (proof.producer.binary.as_deref(), input.binary.as_deref()),
        (proof.producer.ruleset.as_deref(), input.ruleset.as_deref()),
    ];
    let mut unchecked = false;
    let mut mismatch = false;
    for (claim, bytes) in checks {
        if let Some(claim) = claim {
            match bytes {
                Some(bytes) if claim == format!("sha256:{}", sha256_hex(bytes)) => {}
                Some(_) => mismatch = true,
                None => unchecked = true,
            }
        }
    }
    if mismatch {
        Stage::Mismatch
    } else if unchecked {
        Stage::Unchecked
    } else {
        Stage::Matched
    }
}

fn apply_recipe(input: &str, recipe: &Recipe) -> std::result::Result<String, String> {
    if input.len() > 2 * 1024 * 1024 {
        return Err("input limit".into());
    }
    let mut value = input.to_string();
    for op in &recipe.operations {
        value = match op.kind.as_str() {
            "identity" => value,
            "url_component" => url_component(&value, op)?,
            "percent_decode" => {
                let mut current = value;
                for _ in 0..op.passes {
                    current = percent_decode(&current)?;
                }
                current
            }
            "dlp_normalize" => dlp_normalize(&value),
            "lowercase" => value.chars().flat_map(char::to_lowercase).collect(),
            "invisible_strip" => invisible_strip(&value),
            "leetspeak" => value
                .chars()
                .map(|c| match c {
                    '0' => 'o',
                    '1' => 'i',
                    '3' => 'e',
                    '4' => 'a',
                    '5' => 's',
                    '7' => 't',
                    '@' => 'a',
                    '$' => 's',
                    _ => c,
                })
                .collect(),
            "vowel_fold" => value
                .chars()
                .map(|c| match c {
                    'a' | 'e' | 'i' | 'o' | 'u' => 'a',
                    'A' | 'E' | 'I' | 'O' | 'U' => 'A',
                    _ => c,
                })
                .collect(),
            "hex_decode" => canonical_hex(&value)?,
            "base32_decode" => canonical_base32(&value, op.padding)?,
            "base64_decode" => canonical_base64(&value, op.padding)?,
            _ => return Err("unknown operation".into()),
        };
        if value.len() > 1024 * 1024 {
            return Err("output limit".into());
        }
    }
    Ok(value)
}

fn url_component(value: &str, op: &Operation) -> std::result::Result<String, String> {
    let parsed = Url::parse(value).map_err(|_| "invalid absolute URL".to_string())?;
    if parsed.scheme().is_empty() || parsed.host_str().is_none() {
        return Err("invalid absolute URL".into());
    }
    match op.component.as_str() {
        "url" => Ok(value.into()),
        "hostname" => Ok(parsed.host_str().unwrap().into()),
        "path" => Ok(parsed.path().into()),
        "query_key" | "query_value" => {
            // `Url::query_pairs` follows form decoding but is deliberately
            // forgiving of malformed percent escapes. The pinned PR3 profile
            // is not: reject before asking the library to decode.
            validate_percent_escapes(parsed.query().unwrap_or_default())?;
            let values = parsed
                .query_pairs()
                .filter(|(key, _)| key == &op.selector)
                .collect::<Vec<_>>();
            let Some((_, value)) = values.get(op.occurrence as usize) else {
                return Err(format!(
                    "query component: occurrence {} unavailable",
                    op.occurrence
                ));
            };
            if op.component == "query_key" {
                Ok(op.selector.clone())
            } else {
                Ok(value.clone().into_owned())
            }
        }
        _ => Err("unknown URL component".into()),
    }
}

fn validate_percent_escapes(value: &str) -> std::result::Result<(), String> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return Err("query parse: malformed percent escape".into());
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn percent_decode(value: &str) -> std::result::Result<String, String> {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("percent decode".into());
            };
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3])
                .map_err(|_| "percent decode".to_string())?;
            out.push(u8::from_str_radix(pair, 16).map_err(|_| "percent decode".to_string())?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "percent decode output: invalid UTF-8".into())
}
fn canonical_hex(value: &str) -> std::result::Result<String, String> {
    let bytes = hex::decode(value).map_err(|_| "hex decode".to_string())?;
    if hex::encode(&bytes) != value {
        return Err("hex decode: non-canonical encoding".into());
    };
    String::from_utf8(bytes).map_err(|_| "hex output invalid UTF-8".into())
}
fn canonical_base32(value: &str, padding: bool) -> std::result::Result<String, String> {
    let engine = if padding {
        data_encoding::BASE32
    } else {
        data_encoding::BASE32_NOPAD
    };
    let bytes = engine
        .decode(value.as_bytes())
        .map_err(|_| "base32 decode".to_string())?;
    if engine.encode(&bytes) != value {
        return Err("base32 non-canonical".into());
    };
    String::from_utf8(bytes).map_err(|_| "base32 output invalid UTF-8".into())
}
fn canonical_base64(value: &str, padding: bool) -> std::result::Result<String, String> {
    let engine = if padding {
        &STANDARD
    } else {
        &base64::engine::general_purpose::STANDARD_NO_PAD
    };
    let bytes = engine
        .decode(value)
        .map_err(|_| "base64 decode".to_string())?;
    if engine.encode(&bytes) != value {
        return Err("base64 non-canonical".into());
    };
    String::from_utf8(bytes).map_err(|_| "base64 output invalid UTF-8".into())
}

fn invisible_strip(value: &str) -> String {
    value.chars().filter(|c| !is_invisible(*c, true)).collect()
}
fn dlp_normalize(value: &str) -> String {
    let controls_removed: String = value
        .chars()
        .filter(|c| !is_invisible(*c, false))
        .filter(|c| {
            !matches!(
                *c,
                '\u{a0}'
                    | '\u{1680}'
                    | '\u{180e}'
                    | '\u{2000}'..='\u{200a}'
                    | '\u{2028}'..='\u{2029}'
                    | '\u{202f}'
                    | '\u{205f}'
                    | '\u{3000}'
            )
        })
        .collect();
    let nfkc: String = controls_removed.nfkc().collect();
    let mapped: String = nfkc.chars().map(confusable).collect();
    mapped
        .nfd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect()
}

fn is_invisible(c: char, preserve_whitespace_controls: bool) -> bool {
    (c <= '\u{1f}' && (!preserve_whitespace_controls || !matches!(c, '\t' | '\n' | '\r')))
        || c == '\u{7f}'
        || ('\u{80}'..='\u{9f}').contains(&c)
        || matches!(
            c,
            '\u{ad}'
                | '\u{115f}'..='\u{1160}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{e0000}'..='\u{e007f}'
                | '\u{e0100}'..='\u{e01ef}'
        )
}
fn confusable(c: char) -> char {
    match c {
        '\u{0430}' | '\u{03b1}' | '\u{0561}' => 'a',
        '\u{0432}' => 'v',
        '\u{0435}' | '\u{03b5}' => 'e',
        '\u{043d}' | '\u{0570}' | '\u{0127}' => 'h',
        '\u{0456}' | '\u{03b9}' => 'i',
        '\u{043a}' | '\u{03ba}' => 'k',
        '\u{043c}' => 'm',
        '\u{043e}' | '\u{03bf}' | '\u{0585}' | '\u{00f8}' => 'o',
        '\u{0440}' => 'p',
        '\u{0441}' => 'c',
        '\u{0442}' => 't',
        '\u{0443}' => 'y',
        '\u{0445}' => 'x',
        '\u{0458}' => 'j',
        '\u{0455}' | '\u{057d}' | '\u{0167}' => 's',
        '\u{03bd}' => 'v',
        '\u{0578}' | '\u{057c}' => 'n',
        '\u{0111}' => 'd',
        '\u{0142}' => 'l',
        '\u{0299}' => 'B',
        '\u{1d04}' => 'C',
        '\u{1d05}' => 'D',
        '\u{1d07}' => 'E',
        '\u{a730}' => 'F',
        '\u{0262}' => 'G',
        '\u{029c}' => 'H',
        '\u{026a}' => 'I',
        '\u{1d0a}' => 'J',
        '\u{1d0b}' => 'K',
        '\u{029f}' => 'L',
        '\u{1d0d}' => 'M',
        '\u{0274}' => 'N',
        '\u{1d0f}' => 'O',
        '\u{1d18}' => 'P',
        '\u{0280}' => 'R',
        '\u{a731}' => 'S',
        '\u{1d1b}' => 'T',
        '\u{1d1c}' => 'U',
        '\u{1d20}' => 'V',
        '\u{1d21}' => 'W',
        '\u{028f}' => 'Y',
        '\u{1d22}' => 'Z',
        '\u{0410}' | '\u{0391}' | '\u{13aa}' | '\u{1d00}' => 'A',
        '\u{0412}' | '\u{0392}' => 'B',
        '\u{0421}' => 'C',
        '\u{0415}' | '\u{0395}' | '\u{13a1}' => 'E',
        '\u{041d}' | '\u{0397}' => 'H',
        '\u{0406}' | '\u{13a2}' => 'I',
        '\u{0408}' => 'J',
        '\u{041a}' | '\u{039a}' => 'K',
        '\u{041c}' | '\u{039c}' => 'M',
        '\u{041e}' | '\u{039f}' | '\u{0555}' => 'O',
        '\u{0420}' | '\u{03a1}' | '\u{13d2}' => 'P',
        '\u{0405}' | '\u{054d}' | '\u{13da}' => 'S',
        '\u{0422}' | '\u{03a4}' | '\u{13d4}' => 'T',
        '\u{0425}' | '\u{03a7}' => 'X',
        '\u{13b3}' => 'W',
        '\u{0396}' => 'Z',
        '\u{0399}' => 'I',
        '\u{039d}' => 'N',
        '\u{03a5}' => 'Y',
        '\u{054c}' => 'L',
        '\u{00d8}' => 'O',
        '\u{0110}' => 'D',
        '\u{0141}' => 'L',
        '\u{0126}' => 'H',
        '\u{0166}' => 'T',
        '\u{1f170}'..='\u{1f189}' => char::from_u32('A' as u32 + c as u32 - 0x1f170).unwrap(),
        '\u{1f1e6}'..='\u{1f1ff}' => char::from_u32('A' as u32 + c as u32 - 0x1f1e6).unwrap(),
        _ => c,
    }
}

fn recipe_bytes(recipe: &Recipe) -> std::result::Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    frame_into(&mut bytes, b"pipelock/evidence-provenance/recipe/v1");
    frame_into(&mut bytes, recipe.profile.as_bytes());
    frame_into(&mut bytes, &u64_bytes(recipe.operations.len() as u64));
    for operation in &recipe.operations {
        let mut encoded = Vec::new();
        frame_into(&mut encoded, &[kind_byte(&operation.kind)?]);
        frame_into(&mut encoded, &[component_byte(&operation.component)?]);
        frame_into(&mut encoded, operation.selector.as_bytes());
        frame_into(&mut encoded, &operation.occurrence.to_be_bytes());
        frame_into(&mut encoded, &[operation.passes]);
        frame_into(&mut encoded, operation.profile.as_bytes());
        frame_into(&mut encoded, &[u8::from(operation.padding)]);
        frame_into(&mut bytes, &encoded);
    }
    Ok(bytes)
}
fn kind_byte(kind: &str) -> std::result::Result<u8, String> {
    match kind {
        "identity" => Ok(1),
        "url_component" => Ok(2),
        "percent_decode" => Ok(3),
        "dlp_normalize" => Ok(4),
        "lowercase" => Ok(5),
        "invisible_strip" => Ok(6),
        "hex_decode" => Ok(7),
        "base32_decode" => Ok(8),
        "base64_decode" => Ok(9),
        "leetspeak" => Ok(10),
        "vowel_fold" => Ok(11),
        _ => Err("unknown operation".into()),
    }
}
fn component_byte(component: &str) -> std::result::Result<u8, String> {
    match component {
        "" => Ok(0),
        "url" => Ok(1),
        "hostname" => Ok(2),
        "path" => Ok(3),
        "query_key" => Ok(4),
        "query_value" => Ok(5),
        _ => Err("unknown component".into()),
    }
}
fn commitment(key: &[u8], domain: &str, parts: &[Vec<u8>]) -> String {
    let mut mac = Hmac::<HmacSha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    let mut framed = Vec::new();
    frame_into(&mut framed, domain.as_bytes());
    for part in parts {
        frame_into(&mut framed, part)
    }
    mac.update(&framed);
    format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
}
fn frame_into(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value)
}
fn u64_bytes(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}
fn byte_interval_valid(view: &str, start: u64, end: u64) -> bool {
    end > start
        && end <= view.len() as u64
        && (start == 0
            || (start < view.len() as u64 && view.as_bytes()[start as usize] & 0xc0 != 0x80))
        && (end == view.len() as u64
            || (end < view.len() as u64 && view.as_bytes()[end as usize] & 0xc0 != 0x80))
}

#[cfg(test)]
fn byte_boundary(view: &str, offset: u64) -> bool {
    offset == 0
        || offset == view.len() as u64
        || (offset < view.len() as u64 && view.as_bytes()[offset as usize] & 0xc0 != 0x80)
}

fn object<'a>(
    value: &'a Value,
    label: &str,
) -> std::result::Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label}: must be an object"))
}
fn array<'a>(value: &'a Value, label: &str) -> std::result::Result<&'a Vec<Value>, String> {
    value
        .as_array()
        .ok_or_else(|| format!("{label}: must be an array"))
}
fn required<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> std::result::Result<&'a Value, String> {
    object
        .get(key)
        .ok_or_else(|| format!("{label}: missing {key}"))
}
fn string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> std::result::Result<&'a str, String> {
    required(object, key, label)?
        .as_str()
        .ok_or_else(|| format!("{label}: {key} must be a string"))
}
fn optional_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<&'a str>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("{key}: must be a string when present")),
    }
}
fn u64_value(
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) -> std::result::Result<u64, String> {
    required(object, key, label)?
        .as_u64()
        .ok_or_else(|| format!("{label}: {key} must be an unsigned integer"))
}
fn optional_u64(
    object: &Map<String, Value>,
    key: &str,
) -> std::result::Result<Option<u64>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("operation: {key} must be unsigned")),
    }
}
fn exact_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> std::result::Result<(), String> {
    exact_keys_with_optional(object, allowed, &[], label)
}

fn exact_keys_with_optional(
    object: &Map<String, Value>,
    allowed: &[&str],
    optional: &[&str],
    label: &str,
) -> std::result::Result<(), String> {
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || allowed
            .iter()
            .any(|key| !object.contains_key(*key) && !optional.contains(key))
    {
        Err(format!("{label}: unknown or missing field"))
    } else {
        Ok(())
    }
}
fn decode_b64(value: &str, label: &str) -> std::result::Result<Vec<u8>, String> {
    STANDARD
        .decode(value)
        .map_err(|_| format!("{label}: invalid base64"))
}
fn decode_hex(value: &str, length: usize, label: &str) -> std::result::Result<Vec<u8>, String> {
    if value
        .chars()
        .any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
    {
        return Err(format!("{label}: invalid lowercase hex"));
    };
    let bytes = hex::decode(value).map_err(|_| format!("{label}: invalid hex"))?;
    if length != 0 && bytes.len() != length {
        return Err(format!("{label}: wrong length"));
    };
    Ok(bytes)
}
fn valid_digest(value: &str, prefix: &str) -> std::result::Result<(), String> {
    let hex = value
        .strip_prefix(prefix)
        .ok_or_else(|| "digest prefix".to_string())?;
    if hex.len() != 64 {
        return Err("digest length".into());
    };
    decode_hex(hex, 32, "digest").map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct TransformCorpus {
        profile_digest: String,
        vectors: Vec<TransformVector>,
        interval_vectors: Vec<IntervalVector>,
    }

    #[derive(Deserialize)]
    struct TransformVector {
        id: String,
        input_b64: String,
        #[serde(default)]
        output_b64: String,
        #[serde(default)]
        want_error: String,
        transform_profile_digest: Option<String>,
        recipe: Option<Value>,
    }

    #[derive(Deserialize)]
    struct IntervalVector {
        id: String,
        view_b64: String,
        matches: Vec<[u64; 2]>,
        want_error: String,
    }

    #[test]
    fn transform_profile_corpus_is_byte_exact() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/transform-profile/evidence-provenance-v1.json"
        );
        let corpus: TransformCorpus =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let TransformCorpus {
            profile_digest,
            vectors,
            ..
        } = corpus;
        assert_eq!(vectors.len(), 29, "corpus vector count changed");
        for vector in vectors {
            let input = STANDARD.decode(&vector.input_b64).unwrap();
            let result = String::from_utf8(input)
                .map_err(|_| "invalid UTF-8".to_string())
                .and_then(|input| {
                    let recipe = json!({
                        "transform_profile_digest": vector
                            .transform_profile_digest
                            .as_deref()
                            .unwrap_or(&profile_digest),
                        "operations": vector.recipe.unwrap_or_else(|| json!([])),
                    });
                    parse_recipe(&recipe).and_then(|recipe| apply_recipe(&input, &recipe))
                });
            if vector.want_error.is_empty() {
                let output = STANDARD.decode(&vector.output_b64).unwrap();
                assert_eq!(result.unwrap().as_bytes(), output, "{}", vector.id);
            } else {
                let error = result.expect_err(&vector.id);
                assert!(
                    error.contains(&vector.want_error),
                    "{} error={error:?} want={:?}",
                    vector.id,
                    vector.want_error
                );
            }
        }
    }

    #[test]
    fn interval_corpus_exercises_utf8_boundaries_and_ordering() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/transform-profile/evidence-provenance-v1.json"
        );
        let corpus: TransformCorpus =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            corpus.interval_vectors.len(),
            8,
            "interval vector count changed"
        );
        for vector in corpus.interval_vectors {
            let view = String::from_utf8(STANDARD.decode(&vector.view_b64).unwrap()).unwrap();
            let result = validate_interval_corpus_vector(&view, &vector.matches);
            if vector.want_error.is_empty() {
                result.unwrap();
            } else {
                let error = result.expect_err(&vector.id);
                assert!(
                    error.contains(&vector.want_error),
                    "{} error={error:?} want={:?}",
                    vector.id,
                    vector.want_error
                );
            }
        }
    }

    fn validate_interval_corpus_vector(
        view: &str,
        matches: &[[u64; 2]],
    ) -> std::result::Result<(), String> {
        let mut previous: Option<[u64; 2]> = None;
        for bounds in matches {
            let [start, end] = *bounds;
            if end <= start {
                return Err("byte end must be greater".into());
            }
            if end > view.len() as u64 {
                return Err("out of bounds".into());
            }
            if !byte_boundary(view, start) || !byte_boundary(view, end) {
                return Err("splits UTF-8".into());
            }
            if let Some([previous_start, previous_end]) = previous {
                if start < previous_start {
                    return Err("unsorted".into());
                }
                if start == previous_start {
                    return Err("duplicate".into());
                }
                if start < previous_end {
                    return Err("overlap".into());
                }
            }
            previous = Some([start, end]);
        }
        Ok(())
    }

    #[test]
    fn valid_fixture_is_incomplete_without_commitment_key() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let signed = json!({"chain_seq":0,"chain_prev_hash":"genesis","critical_features":["evidence_provenance"],"proof":{"version":PROOF_VERSION,"transform_profile_digest":PROFILE_DIGEST,"sources":[],"producer":{}}});
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({"format":FIXTURE_FORMAT,"entries":[{"signed_b64":STANDARD.encode(&bytes),"signature":format!("ed25519:{}",hex::encode(signing.sign(&bytes).to_bytes()))}],"verification":{"signer_public_key_hex":hex::encode(signing.verifying_key().to_bytes()),"sources":[]}});
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.signature, "verified");
        assert_eq!(report.chain, "verified");
        assert_eq!(report.overall, "incomplete");
        assert_eq!(serde_json::to_string(&report).unwrap(),"{\"trust_roots\":\"fixture supplied; self-attested; not authenticated\",\"authenticated_provenance\":false,\"signature\":\"verified\",\"chain\":\"verified\",\"artifacts\":\"matched\",\"source_commitment\":\"not_checked\",\"view_reproduction\":\"not_checked\",\"location\":\"not_checked\",\"match_commitment\":\"not_checked\",\"overall\":\"incomplete\"}");
    }

    #[test]
    fn unknown_critical_feature_has_its_own_failure_stage() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let signed = json!({"chain_seq":0,"chain_prev_hash":"genesis","critical_features":["unknown"],"proof":{"version":PROOF_VERSION,"transform_profile_digest":PROFILE_DIGEST,"sources":[],"producer":{}}});
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({"format":FIXTURE_FORMAT,"entries":[{"signed_b64":STANDARD.encode(&bytes),"signature":format!("ed25519:{}",hex::encode(signing.sign(&bytes).to_bytes()))}],"verification":{"signer_public_key_hex":hex::encode(signing.verifying_key().to_bytes()),"sources":[]}});
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.failure_stage.as_deref(), Some("critical_features"));
    }

    #[test]
    fn byte_boundary_is_a_location_failure_after_view_reproduction() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let commitment_key = vec![4; 32];
        let recipe = Recipe {
            profile: PROFILE_DIGEST.into(),
            operations: vec![Operation {
                kind: "identity".into(),
                component: String::new(),
                selector: String::new(),
                occurrence: 0,
                passes: 0,
                profile: String::new(),
                padding: false,
            }],
        };
        let view = "A💩B";
        let view_commitment = commitment(
            &commitment_key,
            "pipelock/evidence-provenance/view/v1",
            &[
                u64_bytes(0),
                b"source".to_vec(),
                PROFILE_DIGEST.as_bytes().to_vec(),
                recipe_bytes(&recipe).unwrap(),
                view.as_bytes().to_vec(),
            ],
        );
        let signed = json!({"chain_seq":0,"chain_prev_hash":"genesis","critical_features":["evidence_provenance"],"proof":{"version":PROOF_VERSION,"transform_profile_digest":PROFILE_DIGEST,"producer":{},"sources":[{"source_ordinal":0,"source_id":"source","recipe":{"transform_profile_digest":PROFILE_DIGEST,"operations":[{"kind":"identity"}]},"view_commitment":view_commitment,"matches":[{"match_ordinal":0,"byte_start":2,"byte_end":5,"match_class":"credential","match_commitment":format!("hmac-sha256:{}", "0".repeat(64))}]}]}});
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({"format":FIXTURE_FORMAT,"entries":[{"signed_b64":STANDARD.encode(&bytes),"signature":format!("ed25519:{}",hex::encode(signing.sign(&bytes).to_bytes()))}],"verification":{"signer_public_key_hex":hex::encode(signing.verifying_key().to_bytes()),"commitment_key_hex":hex::encode(&commitment_key),"sources":[{"source_id":"source","bytes_b64":STANDARD.encode(view)}]}});
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.view_reproduction, "reproduced");
        assert_eq!(report.location, "mismatch");
        assert_eq!(report.failure_stage.as_deref(), Some("location"));
    }

    #[test]
    fn artifact_mismatch_outranks_a_missing_sibling_artifact() {
        let signing = SigningKey::from_bytes(&[10; 32]);
        let signed = json!({
            "chain_seq": 0,
            "chain_prev_hash": "genesis",
            "critical_features": ["evidence_provenance"],
            "proof": {
                "version": PROOF_VERSION,
                "transform_profile_digest": PROFILE_DIGEST,
                "sources": [],
                "producer": {
                    "binary_digest": format!("sha256:{}", sha256_hex(b"binary")),
                    "ruleset_digest": format!("sha256:{}", sha256_hex(b"expected-rules"))
                }
            }
        });
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({
            "format": FIXTURE_FORMAT,
            "entries": [{
                "signed_b64": STANDARD.encode(&bytes),
                "signature": format!("ed25519:{}", hex::encode(signing.sign(&bytes).to_bytes()))
            }],
            "verification": {
                "signer_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
                "ruleset_b64": STANDARD.encode("wrong-rules")
            }
        });
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.artifacts, "mismatch");
        assert_eq!(report.failure_stage.as_deref(), Some("artifacts"));
    }

    #[test]
    fn later_available_source_still_invalidates_after_missing_source() {
        let signing = SigningKey::from_bytes(&[11; 32]);
        let commitment_key = vec![5; 32];
        let source = |ordinal: u64, id: &str, commitment: String| {
            json!({
                "source_ordinal": ordinal,
                "source_id": id,
                "recipe": {"transform_profile_digest": PROFILE_DIGEST, "operations": [{"kind":"identity"}]},
                "view_commitment": commitment,
                "matches": [{
                    "match_ordinal": 0,
                    "byte_start": 0,
                    "byte_end": 5,
                    "match_class": "credential",
                    "match_commitment": format!("hmac-sha256:{}", "0".repeat(64))
                }]
            })
        };
        let signed = json!({
            "chain_seq": 0,
            "chain_prev_hash": "genesis",
            "critical_features": ["evidence_provenance"],
            "proof": {
                "version": PROOF_VERSION,
                "transform_profile_digest": PROFILE_DIGEST,
                "producer": {},
                "sources": [
                    source(0, "missing", format!("hmac-sha256:{}", "0".repeat(64))),
                    source(1, "available", format!("hmac-sha256:{}", "0".repeat(64)))
                ]
            }
        });
        let bytes = serde_json::to_vec(&signed).unwrap();
        let fixture = json!({
            "format": FIXTURE_FORMAT,
            "entries": [{
                "signed_b64": STANDARD.encode(&bytes),
                "signature": format!("ed25519:{}", hex::encode(signing.sign(&bytes).to_bytes()))
            }],
            "verification": {
                "signer_public_key_hex": hex::encode(signing.verifying_key().to_bytes()),
                "commitment_key_hex": hex::encode(commitment_key),
                "sources": [{"source_id":"available", "bytes_b64": STANDARD.encode("value")}]
            }
        });
        let report = verify_fixture_bytes(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(report.view_reproduction, "not_checked");
        assert_eq!(report.location, "not_checked");
        assert_eq!(report.match_commitment, "mismatch");
        assert_eq!(report.failure_stage.as_deref(), Some("view_commitment"));
    }

    #[test]
    fn missing_source_before_valid_source_downgrades_aggregate_stages() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p28-missing-source-before-valid-source.json"
        );
        let report = verify_fixture_bytes(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report.view_reproduction, "not_checked");
        assert_eq!(report.location, "not_checked");
        assert_eq!(report.match_commitment, "not_checked");
        assert_eq!(report.overall, "incomplete");
    }

    #[test]
    fn commitment_implementation_matches_frozen_known_answer() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p00-valid.json"
        );
        let report = verify_fixture_bytes(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report.match_commitment, "opened");
        assert_eq!(report.overall, "incomplete");
    }

    #[test]
    fn duplicate_keys_in_envelope_and_signed_payload_are_rejected() {
        let envelope = br#"{"format":"one","format":"two","entries":[],"verification":{}}"#;
        assert!(verify_fixture_bytes(envelope)
            .expect_err("duplicate fixture key must fail")
            .contains("duplicate"));

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/testdata/provenance/p29-duplicate-signed-key.json"
        );
        assert!(verify_fixture_bytes(&std::fs::read(path).unwrap())
            .expect_err("duplicate signed key must fail")
            .contains("duplicate"));
    }

    #[test]
    fn required_fields_are_not_inferred_optional_by_name() {
        let present = json!({"binary_digest": "value"});
        exact_keys(
            present.as_object().unwrap(),
            &["binary_digest"],
            "required field",
        )
        .unwrap();

        let absent = json!({});
        assert!(exact_keys(
            absent.as_object().unwrap(),
            &["binary_digest"],
            "required field",
        )
        .is_err());
    }
}
