// Package unite porte l'unité systemd de l'agent, et sait l'installer — TO-DO 112.
//
// # Pourquoi l'unité vit dans le binaire
//
// Elle était écrite par `rocky.sh`, dans un bloc de texte. Deux conséquences :
//
//   - elle ne portait que `Restart=on-failure`. Pas de délai, pas de borne : un
//     binaire qui meurt au démarrage était relancé sans fin, et rien ne
//     distinguait « en cours de démarrage » de « ne démarrera jamais » ;
//   - une machine déjà installée ne la recevait plus jamais. Corriger le script
//     ne corrige que les installations à venir.
//
// Et il y a pire qu'une unité en retard : une unité en AVANCE. Celle-ci lance
// `vaultaire_client --check` avant chaque démarrage. Posée à côté d'un binaire
// qui ne connaît pas cette option, elle l'empêcherait de démarrer pour
// toujours — sur une machine dont les piles PAM n'ont aucun repli.
//
// L'unité est donc écrite par le binaire qu'elle lance : `vaultaire_client
// --install-unit`. Un binaire ne peut poser que l'unité qu'il sait honorer, et
// il s'en assure en jouant d'abord son propre contrôle.
package unite

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"vaultaire_client/controle"
)

const (
	// Chemin est l'emplacement de l'unité.
	Chemin = "/etc/systemd/system/vaultaire_client.service"
	// Binaire est le programme que l'unité lance — là où `rocky.sh` le dépose.
	Binaire = "/usr/bin/vaultaire_client"
)

// Gabarit est le contenu de l'unité.
//
// # La relance bornée
//
// `RestartSec=5s` : cinq secondes entre deux essais. `StartLimitBurst=3` en
// `StartLimitIntervalSec=60` : trois démarrages manqués en une minute, et
// systemd arrête d'essayer — le service est « failed », `systemctl status` en
// donne le motif, et une supervision peut le voir.
//
// Ces deux dernières lignes vont dans [Unit] : c'est là que systemd les
// documente depuis sa version 230. Il les tolère encore dans [Service], par
// compatibilité, sous un autre nom pour l'intervalle (`StartLimitInterval`) —
// une tolérance qu'on ne veut pas découvrir retirée le jour où elle compte.
// Un test tient leur place.
//
// # Le contrôle avant le démarrage
//
// `ExecStartPre=… --check` : un agent qui ne peut pas démarrer n'est pas lancé,
// et son échec dit pourquoi — voir le paquet controle.
//
// # Ce qui n'y est PAS : le cloisonnement
//
// Pas de `ProtectSystem`, `ProtectHome`, `NoNewPrivileges`… L'unité de Nexus les
// porte ; celle-ci ne le peut pas telle quelle. L'agent crée des comptes,
// écrit dans les dossiers personnels et applique des politiques sur tout le
// système : chacune de ces protections couperait un appliqueur de GPO, et
// aucune n'a été éprouvée sur un poste. Les poser à l'aveugle casserait des
// machines pour une promesse non tenue.
const Gabarit = `# Écrit par « vaultaire_client --install-unit ». Ne pas modifier ici : ce
# fichier est réécrit à chaque mise à jour de l'agent. Un réglage local se
# pose dans /etc/systemd/system/vaultaire_client.service.d/*.conf.
[Unit]
Description=Vaultaire Client Service
After=network.target
# Trois démarrages manqués en une minute : le service passe en échec au lieu
# d'être relancé sans fin. « systemctl status vaultaire_client » dit pourquoi ;
# « systemctl reset-failed vaultaire_client » puis « start » le relance.
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
User=root
Group=root
# Le contrôle de démarrage : configuration, identité, clé privée. Il ne
# modifie rien et n'ouvre aucune connexion.
ExecStartPre=` + Binaire + ` --check
ExecStart=` + Binaire + `
WorkingDirectory=/etc/vaultaire_client
Environment=USER=root
LimitNOFILE=4096
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
`

// Environnement réunit ce dont l'installation dépend. Des fonctions, pour qu'un
// test la joue sans être root ni toucher à systemd.
type Environnement struct {
	CheminUnite string
	Executable  func() (string, error)
	EstRoot     func() bool
	Controler   func() []controle.Constat
	// SystemdActif dit si un systemd dirige cette machine. Dans un conteneur,
	// non : l'unité est écrite, rien n'est rechargé.
	SystemdActif func() bool
	Recharger    func() error
}

// Reel rend l'environnement de la machine.
func Reel() Environnement {
	return Environnement{
		CheminUnite: Chemin,
		Executable: func() (string, error) {
			exe, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(exe)
		},
		EstRoot:   func() bool { return os.Geteuid() == 0 },
		Controler: func() []controle.Constat { return controle.Verifier(controle.CheminsReels()) },
		SystemdActif: func() bool {
			// Le répertoire n'existe que sous un systemd en service.
			_, err := os.Stat("/run/systemd/system")
			return err == nil
		},
		Recharger: func() error {
			if sortie, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl daemon-reload : %v : %s", err, sortie)
			}
			return nil
		},
	}
}

// ErrRefus signale une installation refusée : rien n'a été écrit.
var ErrRefus = errors.New("unité non installée")

// Installer écrit l'unité si elle diffère, et la fait relire par systemd.
//
// Trois refus, AVANT toute écriture :
//
//  1. pas root ;
//  2. ce binaire n'est pas celui que l'unité lancera. L'unité exécute
//     /usr/bin/vaultaire_client : si c'est un autre binaire qui l'écrit — une
//     copie de travail, une version plus récente posée ailleurs — rien ne dit
//     que celui de /usr/bin connaît `--check` ;
//  3. le contrôle de démarrage échoue. L'unité le rejouera avant chaque
//     lancement : la poser maintenant, c'est décider que l'agent ne
//     redémarrera pas.
//
// Le service n'est PAS redémarré : un redémarrage coupe les authentifications
// en cours, et rien ici ne l'exige.
func Installer(env Environnement, w io.Writer) error {
	if !env.EstRoot() {
		fmt.Fprintln(w, "Refus : l'unité systemd s'écrit en root.")
		return ErrRefus
	}
	exe, err := env.Executable()
	if err != nil || exe != Binaire {
		fmt.Fprintf(w, "Refus : l'unité lance %s, et c'est ce binaire-là qui doit l'écrire "+
			"(ici : %s). Lancer « %s --install-unit ».\n", Binaire, exe, Binaire)
		return ErrRefus
	}

	constats := env.Controler()
	if controle.Rapport(w, "Contrôle de démarrage :", constats) > 0 {
		fmt.Fprintln(w, "Refus : l'unité rejoue ce contrôle avant chaque démarrage. "+
			"La poser maintenant empêcherait l'agent de redémarrer. Rien n'a été écrit.")
		return ErrRefus
	}

	actuelle, errLecture := os.ReadFile(env.CheminUnite)
	if errLecture == nil && string(actuelle) == Gabarit {
		fmt.Fprintln(w, "Unité déjà à jour : "+env.CheminUnite)
		return nil
	}

	if errLecture == nil {
		// L'ancienne unité est gardée à côté, sous un nom que systemd ne lit
		// pas : une commande suffit à revenir en arrière.
		precedente := env.CheminUnite + ".precedente"
		if err := os.WriteFile(precedente, actuelle, 0o644); err != nil {
			return fmt.Errorf("sauvegarde de l'unité en place : %w", err)
		}
		fmt.Fprintln(w, "Unité précédente gardée : "+precedente)
	}

	// Écriture par renommage : systemd ne lit jamais un fichier à moitié écrit.
	tmp, err := os.CreateTemp(filepath.Dir(env.CheminUnite), ".vaultaire_client.service-*")
	if err != nil {
		return fmt.Errorf("écriture de l'unité : %w", err)
	}
	nom := tmp.Name()
	_, errEcriture := tmp.WriteString(Gabarit)
	errFermeture := tmp.Close()
	if errEcriture != nil || errFermeture != nil {
		os.Remove(nom)
		return fmt.Errorf("écriture de l'unité : %v %v", errEcriture, errFermeture)
	}
	if err := os.Chmod(nom, 0o644); err != nil {
		os.Remove(nom)
		return fmt.Errorf("droits de l'unité : %w", err)
	}
	if err := os.Rename(nom, env.CheminUnite); err != nil {
		os.Remove(nom)
		return fmt.Errorf("mise en place de l'unité : %w", err)
	}
	fmt.Fprintln(w, "Unité écrite : "+env.CheminUnite)

	if !env.SystemdActif() {
		fmt.Fprintln(w, "systemd ne dirige pas cette machine : rien à recharger.")
		return nil
	}
	if err := env.Recharger(); err != nil {
		return fmt.Errorf("unité écrite mais non relue par systemd : %w", err)
	}
	fmt.Fprintln(w, "systemd a relu l'unité. Le service n'est PAS redémarré : "+
		"le contrôle de démarrage vaudra à son prochain lancement.")
	return nil
}
