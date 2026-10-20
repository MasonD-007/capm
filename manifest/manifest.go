// Package manifest defines the capm.yaml bundle manifest: types, strict
// parsing, and validation.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// FileName is the name of the manifest file inside a bundle.
const FileName = "capm.yaml"

type Manifest struct {
	APIVersion  string      `yaml:"apiVersion" json:"apiVersion"`
	Kind        string      `yaml:"kind" json:"kind"`
	Metadata    Metadata    `yaml:"metadata" json:"metadata"`
	Base        Base        `yaml:"base" json:"base"`
	Interface   Interface   `yaml:"interface" json:"interface"`
	Model       Model       `yaml:"model" json:"model"`
	Permissions Permissions `yaml:"permissions" json:"permissions"`
	Secrets     []Secret    `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	MCP         []MCP       `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	// Context lists bundle-relative file paths.
	Context []string `yaml:"context,omitempty" json:"context,omitempty"`
}

type Metadata struct {
	Name        string   `yaml:"name" json:"name"`
	Version     string   `yaml:"version" json:"version"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Authors     []string `yaml:"authors,omitempty" json:"authors,omitempty"`
}

// Base names the agent runtime: "claude-code" or "opencode".
type Base struct {
	Agent   string `yaml:"agent" json:"agent"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
}

// Interface describes how the installer talks to the agent; only "tty".
type Interface struct {
	Type string `yaml:"type" json:"type"`
}

type Model struct {
	API      string        `yaml:"api" json:"api"`
	Requires ModelRequires `yaml:"requires" json:"requires"`
}

type ModelRequires struct {
	ToolCalling      bool `yaml:"toolCalling" json:"toolCalling"`
	MinContextTokens int  `yaml:"minContextTokens" json:"minContextTokens"`
}

type Permissions struct {
	Egress []string `yaml:"egress,omitempty" json:"egress,omitempty"`
	Mounts []Mount  `yaml:"mounts,omitempty" json:"mounts,omitempty"`
}

// Mount mode is "read-only" or "read-write".
type Mount struct {
	Path string `yaml:"path" json:"path"`
	Mode string `yaml:"mode" json:"mode"`
}

type Secret struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// MCP Secret is optional; when set it must name an entry in Secrets.
type MCP struct {
	Name   string `yaml:"name" json:"name"`
	URL    string `yaml:"url" json:"url"`
	Secret string `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// Parse decodes a manifest strictly: unknown fields are an error. It does not
// validate; call Validate on the result.
func Parse(data []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("manifest: empty document")
		}
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return &m, nil
}
