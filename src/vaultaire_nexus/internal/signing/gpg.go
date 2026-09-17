// Package signing signe les métadonnées des dépôts avec le binaire gpg.
//
// Aucune implémentation OpenPGP maison : la clé reste dans un trousseau gpg
// administré comme d'habitude (import, révocation, sous-clés), et Nexus ne
// fait qu'appeler « gpg --detach-sign » et « gpg --clearsign ».
package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// GPG signe avec une clé d'un trousseau.
type GPG struct {
	Binary string
	Home   string
	KeyID  string
}

func (g *GPG) run(data []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := []string{"--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback"}
	if g.Home != "" {
		base = append(base, "--homedir", g.Home)
	}
	base = append(base, "--local-user", g.KeyID)
	cmd := exec.CommandContext(ctx, g.Binary, append(base, args...)...)
	cmd.Stdin = bytes.NewReader(data)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg : %v : %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out.Bytes(), nil
}

// DetachSign rend une signature détachée en ASCII.
func (g *GPG) DetachSign(data []byte) ([]byte, error) {
	return g.run(data, "--armor", "--detach-sign", "--digest-algo", "SHA256")
}

// ClearSign rend le document signé en clair (InRelease).
func (g *GPG) ClearSign(data []byte) ([]byte, error) {
	return g.run(data, "--clearsign", "--digest-algo", "SHA256")
}

// PublicKey rend la clé publique en ASCII, à distribuer aux clients.
func (g *GPG) PublicKey() ([]byte, error) {
	args := []string{"--batch", "--armor", "--export"}
	if g.Home != "" {
		args = append([]string{"--homedir", g.Home}, args...)
	}
	args = append(args, g.KeyID)
	out, err := exec.Command(g.Binary, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("export de la clé publique : %w", err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, errors.New("clé publique introuvable dans le trousseau")
	}
	return out, nil
}

// Check vérifie au démarrage que la clé signe : mieux vaut refuser de
// démarrer que servir des dépôts dont la signature échoue à chaque publication.
func (g *GPG) Check() error {
	if _, err := exec.LookPath(g.Binary); err != nil {
		return fmt.Errorf("binaire %s introuvable", g.Binary)
	}
	if _, err := g.DetachSign([]byte("vaultaire-nexus")); err != nil {
		return err
	}
	_, err := g.PublicKey()
	return err
}
