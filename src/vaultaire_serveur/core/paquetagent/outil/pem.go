package outil

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// ecrirePEMPrivee écrit la clé en 0600, et refuse d'écraser un fichier : un
// export répété ne doit pas détruire en silence la copie qu'on avait rangée.
func ecrirePEMPrivee(chemin string, cle *rsa.PrivateKey) error {
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("export de la clé : %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cle)}); err != nil {
		_ = f.Close()
		return fmt.Errorf("export de la clé : %w", err)
	}
	return f.Close()
}
