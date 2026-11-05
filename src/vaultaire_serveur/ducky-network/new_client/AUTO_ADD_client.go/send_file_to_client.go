package autoaddclientgo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// RepertoireDistant : où l'agent est installé sur le poste. Fixe, et
// distinct du répertoire de données du core : un core en conteneur écrit dans
// /var/lib/vaultaire, le poste attend toujours /opt/vaultaire.
const RepertoireDistant = "/opt/vaultaire"

// envoyerFichiersClient copie sur le poste le paquet d'agent, puis la
// configuration propre à cette machine — par SFTP, sur la connexion déjà
// ouverte (voir transport_ssh.go).
func envoyerFichiersClient(client *ssh.Client, clientSoftwareID string) error {
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sous-système sftp indisponible sur le poste (« Subsystem sftp » de sshd_config) : %v", err)
	}
	defer func() { _ = sc.Close() }()

	if err := sc.MkdirAll(RepertoireDistant); err != nil {
		return fmt.Errorf("création de %s sur le poste : %v", RepertoireDistant, err)
	}

	// 1. Le paquet d'agent : /opt/vaultaire/vaultaire_client/ sur le poste,
	// comme le faisait « scp -r <paquet>/ hôte:/opt/vaultaire/ ».
	paquet := strings.TrimSuffix(storage.Agent_Package_path, "/")
	if info, err := os.Stat(paquet); err != nil || !info.IsDir() {
		return fmt.Errorf("paquet d'agent absent de ce core (%s) : automatisation.agent_package_path "+
			"ou VAULTAIRE_AGENT_PACKAGE_DIR", paquet)
	}
	logs.Write_Log("DEBUG", "autoadd : envoi du client Vaultaire (sftp)")
	n, err := copierArborescence(sc, paquet, RepertoireDistant+"/vaultaire_client")
	if err != nil {
		return err
	}

	// 2. La configuration de CETTE machine, posée à la racine de
	// /opt/vaultaire. Les fichiers cachés du premier niveau ne partent pas :
	// l'ancien « scp …/<id>/* » ne les prenait pas non plus.
	local := filepath.Join(storage.Client_Conf_path, "clientsoftware", clientSoftwareID)
	entrees, err := os.ReadDir(local)
	if err != nil {
		return fmt.Errorf("configuration de %s introuvable sur ce core (%s) : %v", clientSoftwareID, local, err)
	}
	racineLocale, err := os.OpenRoot(local)
	if err != nil {
		return fmt.Errorf("configuration de %s illisible (%s) : %v", clientSoftwareID, local, err)
	}
	defer func() { _ = racineLocale.Close() }()
	m := 0
	for _, e := range entrees {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		source := filepath.Join(local, e.Name())
		if e.IsDir() {
			k, err := copierArborescence(sc, source, RepertoireDistant+"/"+e.Name())
			if err != nil {
				return err
			}
			m += k
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if err := copierFichier(sc, racineLocale, e.Name(), RepertoireDistant+"/"+e.Name(), info.Mode().Perm()); err != nil {
			return err
		}
		m++
	}

	logs.Write_Log("INFO", fmt.Sprintf("autoadd : client (%d fichier(s)) et configuration %s (%d fichier(s)) copiés", n, clientSoftwareID, m))
	return nil
}
