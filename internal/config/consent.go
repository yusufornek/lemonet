// Package config persists small pieces of local state, such as the user's acceptance of the
// ethical-use terms.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Consent records that the user accepted the ethical-use terms for a given app version.
type Consent struct {
	Accepted   bool      `json:"accepted"`
	Version    string    `json:"version"`
	AcceptedAt time.Time `json:"acceptedAt"`
}

func consentPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "lemonet", "consent.json"), nil
}

func LoadConsent() (Consent, error) {
	path, err := consentPath()
	if err != nil {
		return Consent{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Consent{}, nil
		}
		return Consent{}, err
	}
	var c Consent
	if err := json.Unmarshal(b, &c); err != nil {
		return Consent{}, err
	}
	return c, nil
}

func SaveConsent(version string) error {
	path, err := consentPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	c := Consent{Accepted: true, Version: version, AcceptedAt: time.Now()}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
