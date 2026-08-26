// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestMCPResponseActionForServer_TrustNeverRelaxesSectionAction pins the clamp:
// a per-server trust class may only make response scanning stricter than the
// enclosing response_scanning.action, never weaker. Before the clamp a
// reasoning-class server silently downgraded a configured block section to
// warn.
func TestMCPResponseActionForServer_TrustNeverRelaxesSectionAction(t *testing.T) {
	tests := []struct {
		name          string
		trust         string
		explicitTrust bool
		sectionAction string
		want          string
	}{
		{
			name:          "reasoning under block stays block",
			trust:         ResponseTrustReasoning,
			explicitTrust: true,
			sectionAction: ActionBlock,
			want:          ActionBlock,
		},
		{
			name:          "reasoning under warn warns",
			trust:         ResponseTrustReasoning,
			explicitTrust: true,
			sectionAction: ActionWarn,
			want:          ActionWarn,
		},
		{
			name:          "reasoning under ask stays ask",
			trust:         ResponseTrustReasoning,
			explicitTrust: true,
			sectionAction: ActionAsk,
			want:          ActionAsk,
		},
		{
			name:          "untrusted under warn blocks because trust is stricter",
			trust:         ResponseTrustUntrusted,
			explicitTrust: true,
			sectionAction: ActionWarn,
			want:          ActionBlock,
		},
		{
			name:          "unknown trust under warn still blocks",
			trust:         "totally-bogus",
			explicitTrust: true,
			sectionAction: ActionWarn,
			want:          ActionBlock,
		},
		{
			name:          "unknown trust under block still blocks",
			trust:         "totally-bogus",
			explicitTrust: true,
			sectionAction: ActionBlock,
			want:          ActionBlock,
		},
		{
			name:          "no explicit entry is untrusted and blocks under warn",
			sectionAction: ActionWarn,
			want:          ActionBlock,
		},
		{
			name:          "reasoning with unrankable section action keeps the trust action",
			trust:         ResponseTrustReasoning,
			explicitTrust: true,
			sectionAction: "",
			want:          ActionWarn,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.ResponseScanning.Action = tc.sectionAction
			if tc.explicitTrust {
				cfg.ResponseScanning.MCPServers = []MCPResponseServerTrust{
					{Server: "code-assistant", Trust: tc.trust},
				}
			}
			if got := cfg.MCPResponseActionForServer("code-assistant"); got != tc.want {
				t.Fatalf("MCPResponseActionForServer = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestMCPResponseActionForServer_NilConfigBlocks pins the nil-config path to the
// untrusted class rather than an empty action.
func TestMCPResponseActionForServer_NilConfigBlocks(t *testing.T) {
	var cfg *Config
	if got := cfg.MCPResponseActionForServer("code-assistant"); got != ActionBlock {
		t.Fatalf("nil config action = %q, want %q", got, ActionBlock)
	}
}

// TestStricterAction pins the ordering primitive, including the unrankable
// cases where an action carries no strength evidence.
func TestStricterAction(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{"block beats warn", ActionBlock, ActionWarn, ActionBlock},
		{"warn loses to block", ActionWarn, ActionBlock, ActionBlock},
		{"warn loses to ask", ActionWarn, ActionAsk, ActionAsk},
		{"warn loses to strip", ActionWarn, ActionStrip, ActionStrip},
		{"warn beats allow", ActionWarn, ActionAllow, ActionWarn},
		{"equal keeps a", ActionWarn, ActionWarn, ActionWarn},
		{"unrankable b yields a", ActionWarn, "nonsense", ActionWarn},
		{"empty b yields a", ActionBlock, "", ActionBlock},
		{"unrankable a yields b", "nonsense", ActionWarn, ActionWarn},
		{"neither ranks yields a", "nonsense", "", "nonsense"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := StricterAction(tc.a, tc.b); got != tc.want {
				t.Fatalf("StricterAction(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
