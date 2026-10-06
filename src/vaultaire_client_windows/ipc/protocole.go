// Package ipc porte le canal entre le Credential Provider (DLL C++ chargée par
// Windows) et l'agent Vaultaire.
//
// # Le canal : un TUBE NOMMÉ, pas un port
//
// Le Credential Provider tourne DANS LogonUI.exe, le processus qui dessine
// l'écran de connexion. Trois conséquences dictent le choix :
//
//   - ce qui y plante fait disparaître l'écran de connexion de la machine. Le
//     code chargé là doit donc être le plus petit possible : un tube nommé se
//     lit avec l'API Win32 déjà présente, là où une pile gRPC y ferait entrer
//     protobuf, ses threads et son TLS ;
//   - un tube nommé n'ouvre AUCUN port. Un socket sur la boucle locale est
//     joignable par tout utilisateur de la machine, et le mot de passe en clair
//     de chaque connexion passe par ce canal ;
//   - le tube porte une liste de contrôle d'accès : seuls SYSTEM et les
//     administrateurs s'y connectent. C'est la même décision que le socket PAM
//     de l'agent Linux, qui vit dans un répertoire 0700 et refuse tout appelant
//     non root.
//
// # Le format : le MÊME que le canal PAM
//
// Une requête JSON par connexion, une réponse JSON, puis fermeture. C'est le
// protocole du canal PAM de l'agent Linux, repris tel quel : les deux portes
// posent la même question au même serveur, et une seule forme de message évite
// d'avoir deux vérités sur ce qu'« authentifié » veut dire.
package ipc

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// NomTube est le nom du tube, côté agent comme côté Credential Provider.
//
// Écrit ici ET dans le C++ (vaultaire_pipe.h) : les deux vivent dans des
// langages différents, rien ne peut les tenir liés à la compilation. Les faire
// diverger donne un échec net — « le service Vaultaire ne répond pas » — et non
// un comportement douteux, ce qui est le bon côté du piège.
const NomTube = `\\.\pipe\vaultaire_agent`

// Types de requêtes.
const (
	// TypeAuth : vérifier un mot de passe, et provisionner le compte local.
	// C'est ce que demande le Credential Provider à l'ouverture de session.
	TypeAuth = "auth"
	// TypeCheck : vérifier un mot de passe SANS rien provisionner. Prévu pour
	// un déverrouillage d'écran, où le compte existe forcément déjà.
	TypeCheck = "check"
	// TypeEtat : l'agent est-il raccordé à un core ? Le Credential Provider
	// s'en sert pour dire à l'utilisateur pourquoi il ne peut pas se connecter,
	// AVANT qu'il ait tapé son mot de passe.
	TypeEtat = "etat"
)

// Statuts de réponse. Le Credential Provider ne connaît que ces quatre-là.
const (
	// StatutSucces : mot de passe validé par le core, compte local prêt.
	StatutSucces = "success"
	// StatutRefus : le core a refusé. Mot de passe faux, compte inconnu, droit
	// absent : le motif n'est PAS détaillé au poste, c'est le core qui le
	// journalise.
	StatutRefus = "failed"
	// StatutIndisponible : aucun core joignable. À distinguer d'un refus —
	// l'utilisateur doit savoir que ce n'est pas son mot de passe qui est en
	// cause, et l'administrateur que c'est le réseau.
	StatutIndisponible = "unavailable"
	// StatutDelai : le core n'a pas répondu à temps.
	StatutDelai = "timeout"
)

// Requete est ce que le Credential Provider envoie.
type Requete struct {
	Type string `json:"type"`
	// Utilisateur, sous la forme « alice@domaine.fr ». Le domaine décide de ce
	// que le core cherche ; un nom sans domaine est refusé côté core.
	Utilisateur string `json:"user"`
	MotDePasse  string `json:"password,omitempty"`

	// Code est le second facteur saisi dans la tuile (TO-DO 95). « 0000 » pour
	// un compte qui n'en a pas — c'est ce que dit le libellé du champ.
	//
	// SANS `omitempty`, contrairement au mot de passe : c'est la PRÉSENCE de ce
	// champ qui dit au core qu'il parle à un agent récent. Omis parce que vide,
	// il se confondrait avec un agent ancien, et le core laisserait passer sans
	// second facteur.
	Code string `json:"otp"`
}

// Reponse est ce que l'agent rend.
type Reponse struct {
	Statut string `json:"status"`
	// Administrateur : le core a dit que ce compte est administrateur de la
	// machine. L'agent l'inscrit dans le groupe local Administrateurs.
	Administrateur bool `json:"is_admin,omitempty"`
	// Compte local réellement utilisé pour ouvrir la session Windows. Il DIFFÈRE
	// de Utilisateur : Windows n'accepte pas « @ » dans un nom de compte local
	// (voir compte.NomLocal).
	CompteLocal string `json:"local_account,omitempty"`
	// Message lisible, pour le journal du poste et l'écran de connexion. Jamais
	// le motif exact d'un refus d'authentification.
	Message string `json:"message,omitempty"`
	// Raccorde dit si l'agent a une session ouverte avec un core (type « etat »).
	Raccorde bool `json:"connected,omitempty"`
}

// TailleMaxRequete borne ce qu'on accepte de lire sur le tube.
//
// Sans borne, un appelant local ouvrirait une connexion et enverrait un flux
// sans fin : la mémoire de l'agent monterait jusqu'à sa mort, et l'écran de
// connexion de la machine n'aurait plus personne pour répondre.
const TailleMaxRequete = 8 * 1024

// nomValide : les mêmes caractères que le canal PAM de l'agent Linux.
//
// Une liste blanche et non une liste noire : ce nom part dans une trame dont
// les champs sont séparés par des sauts de ligne, et il sert à nommer un compte
// local Windows. Tout ce qui n'est pas explicitement permis est refusé.
var nomValide = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)

// LongueurMaxNom borne le nom d'utilisateur.
//
// 104 : de quoi écrire un compte et son domaine, sans permettre une ligne
// démesurée dans une trame ou dans le journal.
const LongueurMaxNom = 104

// ValiderRequete contrôle une requête AVANT qu'elle ne touche au réseau.
//
// Le contrôle est fait ici, et non seulement côté core : une chaîne portant un
// saut de ligne décalerait les champs de la trame 03_01, c'est-à-dire ferait
// lire le mot de passe comme un nom d'utilisateur, ou l'inverse.
func ValiderRequete(r Requete) error {
	switch r.Type {
	case TypeAuth, TypeCheck, TypeEtat:
	default:
		return fmt.Errorf("type de requête inconnu : %q", r.Type)
	}
	if r.Type == TypeEtat {
		return nil
	}
	if r.Utilisateur == "" {
		return fmt.Errorf("utilisateur requis")
	}
	if len(r.Utilisateur) > LongueurMaxNom {
		return fmt.Errorf("nom d'utilisateur trop long (%d caractères)", len(r.Utilisateur))
	}
	if !nomValide.MatchString(r.Utilisateur) {
		return fmt.Errorf("nom d'utilisateur invalide : %q", r.Utilisateur)
	}
	if r.MotDePasse == "" {
		return fmt.Errorf("mot de passe requis")
	}
	// Un mot de passe peut contenir à peu près n'importe quoi, SAUF ce qui
	// casserait la trame : le saut de ligne en sépare les champs.
	if strings.ContainsAny(r.MotDePasse, "\n\r") {
		return fmt.Errorf("mot de passe contenant un saut de ligne")
	}
	return nil
}

// LireRequete lit une requête sur le tube, bornée en taille.
func LireRequete(r io.Reader) (Requete, error) {
	var req Requete
	decodeur := json.NewDecoder(io.LimitReader(r, TailleMaxRequete))
	if err := decodeur.Decode(&req); err != nil {
		return Requete{}, fmt.Errorf("requête illisible : %w", err)
	}
	return req, nil
}

// EcrireReponse écrit la réponse. Une seule ligne JSON : le lecteur C++ lit
// jusqu'à la fin du message, sans analyseur.
func EcrireReponse(w io.Writer, rep Reponse) error {
	donnees, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = w.Write(append(donnees, '\n'))
	return err
}
