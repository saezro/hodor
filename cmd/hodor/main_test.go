package main

import (
	"testing"
	"time"

	"github.com/saezro/hodor/internal/config"
	"gopkg.in/yaml.v3"
)

type apiKeysDoc struct {
	APIKeys []config.APIKey `yaml:"api_keys"`
}

func TestKeyYAML_WildcardServices(t *testing.T) {
	block := keyYAML("abcd1234", "test key", "deadbeef", "*", "open,close,status", time.Now().UTC())

	var doc apiKeysDoc
	if err := yaml.Unmarshal([]byte(block), &doc); err != nil {
		t.Fatalf("yaml.Unmarshal failed on wildcard services block: %v\nblock:\n%s", err, block)
	}
	if len(doc.APIKeys) != 1 {
		t.Fatalf("expected 1 api key, got %d", len(doc.APIKeys))
	}
	k := doc.APIKeys[0]
	if k.ID != "abcd1234" {
		t.Errorf("ID = %q, want abcd1234", k.ID)
	}
	if k.Name != "test key" {
		t.Errorf("Name = %q, want %q", k.Name, "test key")
	}
	if k.Hash != "deadbeef" {
		t.Errorf("Hash = %q, want deadbeef", k.Hash)
	}
	if len(k.Services) != 1 || k.Services[0] != "*" {
		t.Errorf("Services = %v, want [*]", k.Services)
	}
	if len(k.Actions) != 3 || k.Actions[0] != "open" || k.Actions[1] != "close" || k.Actions[2] != "status" {
		t.Errorf("Actions = %v, want [open close status]", k.Actions)
	}
}

func TestKeyYAML_MultipleServices(t *testing.T) {
	block := keyYAML("ef012345", "another key", "cafebabe", "a,b", "open,status", time.Now().UTC())

	var doc apiKeysDoc
	if err := yaml.Unmarshal([]byte(block), &doc); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v\nblock:\n%s", err, block)
	}
	if len(doc.APIKeys) != 1 {
		t.Fatalf("expected 1 api key, got %d", len(doc.APIKeys))
	}
	k := doc.APIKeys[0]
	if len(k.Services) != 2 || k.Services[0] != "a" || k.Services[1] != "b" {
		t.Errorf("Services = %v, want [a b]", k.Services)
	}
	if len(k.Actions) != 2 || k.Actions[0] != "open" || k.Actions[1] != "status" {
		t.Errorf("Actions = %v, want [open status]", k.Actions)
	}
}
