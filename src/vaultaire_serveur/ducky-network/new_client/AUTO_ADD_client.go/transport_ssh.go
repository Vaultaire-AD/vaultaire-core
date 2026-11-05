package autoaddclientgo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"vaultaire/core/logs"
)

// Le transport SSH de « vlt create -c … -join », sans binaire externe — 2.3.
//
// # Ce qu'il remplace
//
// L'installation à distance lançait `ssh-keyscan`, `ssh` et `scp` : le core
// dépendait donc d'un client OpenSSH installé à côté de lui, et de
// `~/.ssh/known_hosts` dans le répertoire personnel du compte qui le fait
// tourner. Deux choses qu'une image minimale — sans shell, sans gestionnaire de
// paquets, système de fichiers en lecture seule, compte sans répertoire
// personnel — n'a pas.
//
// Le core parle maintenant SSH lui-même (golang.org/x/crypto/ssh, déjà dans ses
// dépendances) et copie par SFTP (github.com/pkg/sftp, idem). Le poste distant
// n'a rien de plus à offrir qu'avant : OpenSSH sert le sous-système sftp par
// défaut sur Rocky, Debian et Ubuntu — et `scp` lui-même passe par SFTP depuis
// OpenSSH 9.
//
// # La clé d'hôte
//
// Même règle qu'avant, rendue explicite : une clé inconnue est apprise et
// inscrite (le `ssh-keyscan` d'avant faisait exactement cela, à chaque
// installation), une clé connue est vérifiée. Une clé CHANGÉE n'était pas
// refusée — `ssh-keyscan` ajoutait la nouvelle ligne avant que `ssh` ne
// compare — et ne l'est toujours pas : un poste réinstallé se rejoint. Mais le
// changement est maintenant JOURNALISÉ, avec l'ancienne et la nouvelle
// empreinte, au lieu de passer sans trace.
//
// Le fichier des clés connues vit à côté de la clé de connexion, dans le
// répertoire de données du core (VAULTAIRE_DATA_DIR) — plus dans le HOME du
// compte, qu'un conteneur rootless n'a pas.

// DelaiConnexionSSH borne l'établissement de la connexion.
const DelaiConnexionSSH = 15 * time.Second

// connexionSSH ouvre une connexion authentifiée par la clé privée du fichier.
func connexionSSH(utilisateur, cheminCle, hote string, port int) (*ssh.Client, error) {
	pem, err := os.ReadFile(cheminCle)
	if err != nil {
		return nil, fmt.Errorf("lecture de la clé de connexion %s : %v", cheminCle, err)
	}
	signataire, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("clé de connexion %s illisible : %v", cheminCle, err)
	}
	connues := filepath.Join(filepath.Dir(cheminCle), "known_hosts")
	cfg := &ssh.ClientConfig{
		User:            utilisateur,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signataire)},
		HostKeyCallback: retenirCleHote(connues),
		Timeout:         DelaiConnexionSSH,
	}
	adresse := net.JoinHostPort(hote, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", adresse, cfg)
	if err != nil {
		return nil, expliquerEchecConnexion(hote, port, err)
	}
	return client, nil
}

// expliquerEchecConnexion complète une erreur de connexion par ce qu'il faut
// vérifier — le message de ssh-keyscan d'avant (TO-DO 71) le faisait déjà.
func expliquerEchecConnexion(hote string, port int, err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("connexion SSH à %s port %d impossible : %v\n"+
			"  À vérifier, dans cet ordre :\n"+
			"    1. sshd écoute-t-il sur ce port ?   ss -tlnp | grep sshd\n"+
			"    2. le port est-il joignable du core ? (réseau, NetworkPolicy, pare-feu)\n"+
			"  Si sshd écoute sur un autre port, indiquez-le : -join %s:PORT <user>",
			hote, port, err, hote)
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("connexion SSH à %s port %d refusée : la clé publique du core n'est pas "+
			"dans authorized_keys du compte visé (%v)", hote, port, err)
	}
	return fmt.Errorf("connexion SSH à %s port %d : %v", hote, port, err)
}

// verrouConnues sérialise les écritures du fichier des clés connues : deux
// installations simultanées ne doivent pas entrelacer leurs lignes.
var verrouConnues sync.Mutex

// retenirCleHote rend le contrôle de clé d'hôte décrit en tête de fichier.
func retenirCleHote(fichier string) ssh.HostKeyCallback {
	return func(nomHote string, distant net.Addr, cle ssh.PublicKey) error {
		verrouConnues.Lock()
		defer verrouConnues.Unlock()

		hote := cleDHote(nomHote)
		ligne := hote + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cle)))
		empreinte := ssh.FingerprintSHA256(cle)

		anciennes, err := clesConnues(fichier, hote, cle.Type())
		if err != nil {
			return err
		}
		for _, a := range anciennes {
			if bytes.Equal(a.Marshal(), cle.Marshal()) {
				return nil
			}
		}
		if len(anciennes) > 0 {
			logs.Write_LogCode("WARNING", logs.CodeNetConnection, fmt.Sprintf(
				"autoadd: SECURITY clé d'hôte %s CHANGÉE pour %s : %s (connue : %s) — "+
					"acceptée comme avant le 2.3 (poste réinstallé ?) ; vérifiez-la sur le poste : "+
					"ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub",
				cle.Type(), hote, empreinte, ssh.FingerprintSHA256(anciennes[0]),
				strings.TrimPrefix(cle.Type(), "ssh-")))
		} else {
			logs.Write_Log("INFO", fmt.Sprintf("autoadd: clé d'hôte de %s apprise : %s %s", hote, cle.Type(), empreinte))
		}
		return ajouterLigne(fichier, ligne)
	}
}

// cleDHote rend la forme known_hosts : « hote » sur 22, « [hote]:port » sinon.
func cleDHote(nomHote string) string {
	h, p, err := net.SplitHostPort(nomHote)
	if err != nil {
		return nomHote
	}
	if p == "22" {
		return h
	}
	return "[" + h + "]:" + p
}

// clesConnues rend les clés de ce type déjà inscrites pour cet hôte.
func clesConnues(fichier, hote, typ string) ([]ssh.PublicKey, error) {
	f, err := os.Open(fichier)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lecture de %s : %v", fichier, err)
	}
	defer f.Close()
	var cles []ssh.PublicKey
	lecteur := bufio.NewScanner(f)
	lecteur.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for lecteur.Scan() {
		champs := strings.Fields(lecteur.Text())
		if len(champs) < 3 || strings.HasPrefix(champs[0], "#") || champs[1] != typ {
			continue
		}
		correspond := false
		for _, h := range strings.Split(champs[0], ",") {
			correspond = correspond || h == hote
		}
		if !correspond {
			continue
		}
		cle, _, _, _, err := ssh.ParseAuthorizedKey([]byte(champs[1] + " " + champs[2]))
		if err == nil {
			cles = append(cles, cle)
		}
	}
	return cles, lecteur.Err()
}

func ajouterLigne(fichier, ligne string) error {
	if err := os.MkdirAll(filepath.Dir(fichier), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(fichier, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("écriture de %s : %v", fichier, err)
	}
	defer f.Close()
	_, err = f.WriteString(ligne + "\n")
	return err
}

// executer lance une commande distante ; sortie standard et erreur standard
// sont écrites dans sortie (qui peut être nil).
func executer(client *ssh.Client, commande string, sortie io.Writer) error {
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ouverture d'une session SSH : %v", err)
	}
	defer session.Close()
	if sortie != nil {
		session.Stdout = sortie
		session.Stderr = sortie
	}
	return session.Run(commande)
}

// lireSortie lance une commande et rend sa sortie standard.
func lireSortie(client *ssh.Client, commande string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ouverture d'une session SSH : %v", err)
	}
	defer session.Close()
	var out, errOut bytes.Buffer
	session.Stdout = &out
	session.Stderr = &errOut
	if err := session.Run(commande); err != nil {
		return "", fmt.Errorf("%v\n%s", err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}

// copierArborescence copie le CONTENU de source dans destination, sur le
// poste, en gardant les droits de chaque fichier (le bit d'exécution des
// binaires et des modules en dépend) — ce que faisait `scp -r`.
func copierArborescence(sc *sftp.Client, source, destination string) (int, error) {
	n := 0
	err := filepath.Walk(source, func(chemin string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, chemin)
		if err != nil {
			return err
		}
		cible := path.Join(destination, filepath.ToSlash(rel))
		switch {
		case info.IsDir():
			if err := sc.MkdirAll(cible); err != nil {
				return fmt.Errorf("création de %s sur le poste : %v", cible, err)
			}
			return nil
		case !info.Mode().IsRegular():
			// Un lien ou un fichier spécial dans le paquet n'a pas à voyager :
			// scp le suivait, ce qui pouvait copier n'importe quoi de l'hôte.
			logs.Write_Log("WARNING", "autoadd: "+chemin+" ignoré : ni fichier ni répertoire")
			return nil
		}
		if err := copierFichier(sc, chemin, cible, info.Mode().Perm()); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}

// copierFichier écrit un fichier sur le poste, puis pose ses droits.
func copierFichier(sc *sftp.Client, source, cible string, mode os.FileMode) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := sc.OpenFile(cible, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("ouverture de %s sur le poste : %v", cible, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return fmt.Errorf("copie de %s vers %s : %v", source, cible, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("fermeture de %s sur le poste : %v", cible, err)
	}
	if err := sc.Chmod(cible, mode); err != nil {
		return fmt.Errorf("droits de %s sur le poste : %v", cible, err)
	}
	return nil
}
