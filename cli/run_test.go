package main

import "testing"

func TestDefaultEnvRegistry(t *testing.T) {
	t.Setenv("CAPM_REGISTRY", "")
	if got := defaultEnv().registry; got != "https://capm.masondrake.dev" {
		t.Fatalf("default: %s", got)
	}
	t.Setenv("CAPM_REGISTRY", "http://localhost:8080")
	if got := defaultEnv().registry; got != "http://localhost:8080" {
		t.Fatalf("override: %s", got)
	}
}
