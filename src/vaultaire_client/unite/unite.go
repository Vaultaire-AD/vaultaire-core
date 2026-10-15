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
// # Le cloisonnement — TO-DO 168
//
// L'agent crée des comptes, écrit dans les dossiers personnels et applique des
// politiques sur tout le système : il ne peut pas porter le cloisonnement de
// l'unité de Nexus. Mais il peut porter ce qui ne lui coûte RIEN — les
// directives qui interdisent une chose qu'aucun de ses chemins ne fait, lui
// ni les commandes qu'il lance (systemctl, nft, chage, usermod, gpasswd,
// setfacl, sysctl, auditctl, modprobe, grub2-mkconfig, restorecon…). Chacune
// a été confrontée au code ; voir Cloisonnement ci-dessous, et ce qui est
// refusé dans Exclues.
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
` + Cloisonnement + `
[Install]
WantedBy=multi-user.target
`

// Cloisonnement : les directives que l'agent porte, chacune parce qu'aucun de
// ses chemins ne fait ce qu'elle interdit (TO-DO 168).
//
// Une directive inconnue d'un systemd ancien (ProtectKernelLogs avant la 244 —
// Rocky 8) est ignorée par lui avec un avertissement : jamais un refus de
// démarrer.
const Cloisonnement = `# Cloisonnement (TO-DO 168) : ce que l'agent ne fait jamais. Ce qu'il fait —
# écrire dans /etc, /home et /boot, régler /proc/sys, décharger un module,
# changer de domaine SELinux — reste permis : voir unite.go, « Exclues ».
# Changer de domaine d'exécution (personality) : jamais.
LockPersonality=yes
# Ordonnancement temps réel : jamais.
RestrictRealtime=yes
# Créer un fichier setuid ou setgid : jamais — les GPO n'expriment que trois
# chiffres de permissions (gpo/registry.go, parseFileMode).
RestrictSUIDSGID=yes
# Créer un espace de noms : ni l'agent, ni les commandes qu'il lance.
RestrictNamespaces=yes
# Appels système d'une autre architecture (32 bits sur 64) : jamais.
SystemCallArchitectures=native
# Lire le tampon du noyau (dmesg, /dev/kmsg) : jamais.
ProtectKernelLogs=yes
# /sys/fs/cgroup en lecture seule : les limites des comptes passent par des
# fichiers de /etc/systemd et « systemctl daemon-reload », pas par cgroupfs.
ProtectControlGroups=yes
# Unix (PAM, NSS, D-Bus), IP (le réseau Ducky, le DNS), netlink (nft,
# auditctl, les interfaces réseau). Rien d'autre — AF_PACKET compris.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
`

// Exclues : les directives que l'agent ne peut PAS porter, et pourquoi. Un test
// vérifie qu'aucune n'est dans le gabarit ; les ajouter demande de lever la
// raison d'abord.
var Exclues = map[string]string{
	"ProtectSystem":         "les GPO écrivent dans /etc (sshd, sudoers, dépôts, journald…) et /boot (grub2-mkconfig)",
	"ProtectHome":           "l'agent crée les dossiers personnels et y applique le scope utilisateur",
	"NoNewPrivileges":       "elle interdit les transitions SELinux de l'agent (vers useradd_t, setfiles_t — TO-DO 22)",
	"ProtectKernelTunables": "le module sysctl règle /proc/sys (sysctl -p), setenforce écrit dans /sys/fs/selinux",
	"ProtectKernelModules":  "le durcissement décharge des modules (modprobe -r)",
	"ProtectClock":          "elle pose une liste de périphériques autorisés, que les commandes des GPO n'ont jamais été éprouvées sous",
	// TO-DO 181 : la raison d'avant — « l'ancien tube PAM vit dans /tmp » —
	// ne tenait plus. L'agent n'y écoute plus depuis longtemps ; il ne fait que
	// RETIRER au démarrage un ancien tube laissé là. La vraie raison est ailleurs.
	"PrivateTmp": "un /tmp et un /var/tmp privés : la purge file_retention d'une GPO machine, permise sur ces deux " +
		"dossiers, viderait ceux de l'agent et pas ceux du système — sans erreur. Et le retrait de l'ancien " +
		"tube PAM de /tmp (pamstate.LegacySocketPath) ne verrait plus le vrai /tmp",
	"PrivateDevices":         "même raison que ProtectClock, et grub2-mkconfig lit les disques",
	"MemoryDenyWriteExecute": "elle vaut aussi pour les commandes lancées, dont certaines (interpréteurs) écrivent du code exécutable",
	"ProtectHostname":        "un espace de noms UTS privé : un nom de machine posé par une commande ne vaudrait que pour l'agent",
	"SystemCallFilter": "useradd, chage, setfacl, auditctl… : un filtre demande de relever leurs appels système sur " +
		"un poste — automatisation/releve-appels-agent.sh (TO-DO 181), puis TO-DO 201",
}

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
