// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// The routing bug these tests exist for was invisible to every existing CLI
// test, and the reason is worth stating: a test that calls cmd.SetOut(&buf) IS
// setting the writer cobra's Print* family resolves to, so the output appears
// in the buffer the test named "stdout" whether or not production would send it
// there. Production never called SetOut, so Print* fell through to stderr.
//
// These tests capture the real os.Stdout and os.Stderr file descriptors and
// drive the root command with no writer overrides at all, which is the state a
// person running the binary is in.

// captureStd runs fn with the process's real stdout and stderr replaced by
// pipes, and returns what was written to each.
func captureStd(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	// Drain both pipes concurrently. A command that writes more than the pipe
	// buffer would otherwise block forever with the reader still parked.
	outCh := make(chan []byte, 1)
	errCh := make(chan []byte, 1)
	go func() { var b bytes.Buffer; _, _ = io.Copy(&b, outR); outCh <- b.Bytes() }()
	go func() { var b bytes.Buffer; _, _ = io.Copy(&b, errR); errCh <- b.Bytes() }()

	func() {
		defer func() {
			os.Stdout, os.Stderr = origOut, origErr
			_ = outW.Close()
			_ = errW.Close()
		}()
		fn()
	}()

	return string(<-outCh), string(<-errCh)
}

func TestRootCommandSendsResultsToStdout(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // a fragment of the result that must reach stdout
	}{
		{name: "version", args: []string{"version"}, want: "pipelock version"},
		{name: "audit score", args: []string{"audit", "score"}, want: "Pipelock Config Security Score"},
		{name: "generate docker-compose", args: []string{"generate", "docker-compose"}, want: "services:"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var runErr error
			stdout, stderr := captureStd(t, func() {
				// Deliberately no SetOut or SetErr. Overriding either one here
				// would reintroduce exactly the blindness this test exists to
				// remove.
				cmd := rootCmd()
				cmd.SetArgs(tc.args)
				runErr = cmd.Execute()
			})
			if runErr != nil {
				t.Fatalf("%v: %v", tc.args, runErr)
			}
			if !strings.Contains(stdout, tc.want) {
				t.Errorf("result did not reach stdout.\nstdout: %q\nstderr: %q", stdout, stderr)
			}
		})
	}
}

func TestRootCommandKeepsDiagnosticsOffStdout(t *testing.T) {
	// Routing results to stdout must not drag diagnostics along with them.
	// PrintErr* resolves through a separate writer that this change does not
	// touch, so a failure report stays on stderr and a caller redirecting
	// stdout to a file still sees why the command failed.
	var runErr error
	stdout, stderr := captureStd(t, func() {
		cmd := rootCmd()
		cmd.SetArgs([]string{"check", "--config", "/nonexistent-pipelock-config.yaml"})
		runErr = cmd.Execute()
	})
	if runErr == nil {
		t.Fatal("check accepted a config path that does not exist")
	}
	if !strings.Contains(stderr, "Config validation FAILED") {
		t.Errorf("failure report did not reach stderr.\nstderr: %q", stderr)
	}
	if strings.Contains(stdout, "Config validation FAILED") {
		t.Errorf("failure report leaked onto stdout.\nstdout: %q", stdout)
	}
}
