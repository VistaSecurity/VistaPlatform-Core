package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Preserve unrelated settings and YAML comments. A restart-only change is not
// accepted unless it is durable; a file error must surface as a setting failure.
func (s *Sensor) persistCaptureSetting(key string, value any) error {
	if s.configPath == "" {
		return fmt.Errorf("cannot save %s: no configuration file path", key)
	}
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("read capture configuration: %w", err)
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return fmt.Errorf("parse capture configuration: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("configuration must contain exactly one YAML document")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("configuration must be a YAML mapping")
	}
	// Decode also validates duplicate mapping keys before editing anything.
	var check map[string]any
	if err := doc.Decode(&check); err != nil {
		return fmt.Errorf("invalid capture configuration: %w", err)
	}
	root := doc.Content[0]
	var capture *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "capture" {
			capture = root.Content[i+1]
			break
		}
	}
	if capture == nil {
		capture = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "capture"}, capture)
	}
	if capture.Kind != yaml.MappingNode {
		return fmt.Errorf("capture configuration must be a YAML mapping")
	}
	var encoded yaml.Node
	if err := encoded.Encode(value); err != nil {
		return err
	}
	found := false
	for i := 0; i < len(capture.Content); i += 2 {
		if capture.Content[i].Value == key {
			old := capture.Content[i+1]
			encoded.HeadComment, encoded.LineComment, encoded.FootComment = old.HeadComment, old.LineComment, old.FootComment
			capture.Content[i+1] = &encoded
			found = true
			break
		}
	}
	if !found {
		capture.Content = append(capture.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &encoded)
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	// Match the installer's two-space lists: interface updates also edit them.
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	out := output.Bytes()
	info, err := os.Stat(s.configPath)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.configPath), ".sensor-config-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.configPath); err != nil {
		return fmt.Errorf("save capture configuration: %w", err)
	}
	return nil
}
