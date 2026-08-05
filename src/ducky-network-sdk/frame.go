package duckynetwork

import (
	"fmt"
	"strings"
)

// Codes de trames du protocole Ducky.
//
// La liste ne prétend pas être exhaustive : elle porte ce que le SDK sait
// produire ou reconnaître. Une trame absente d'ici n'est pas interdite, elle est
// simplement déléguée telle quelle au consommateur (voir splitter.go).
const (
	// 01 — poignée de main et enrôlement. Communs à TOUS les clients.
	Trame01_01 = "01_01" // demande d'authentification serveur
	Trame01_02 = "01_02" // réponse : clé de session, chiffrée pour nous
	Trame01_03 = "01_03" // enrôlement : clé publique + clé d'enrôlement
	Trame01_04 = "01_04" // enrôlement accepté : identifiant attribué
	Trame01_05 = "01_05" // enrôlement refusé
	Trame01_06 = "01_06" // enrôlement limité en débit

	// 02 — authentification. Commune à TOUS les clients.
	Trame02_01 = "02_01"
	Trame02_03 = "02_03"
	Trame02_04 = "02_04"
	Trame02_05 = "02_05"
	Trame02_07 = "02_07"

	// 04 — cluster. Hôtes (01..08) et services (09..14).
	Trame04_01 = "04_01"
	Trame04_02 = "04_02"
	Trame04_03 = "04_03"
	Trame04_04 = "04_04"
	Trame04_07 = "04_07"
	Trame04_08 = "04_08"
	Trame04_09 = "04_09" // enregistrement d'un service
	Trame04_10 = "04_10" // enregistrement accepté
	Trame04_11 = "04_11" // enregistrement refusé
	Trame04_12 = "04_12" // battement de cœur
	Trame04_13 = "04_13" // battement acquitté
	Trame04_14 = "04_14" // sortie propre
)

// TargetCore est la destination des trames montantes.
const TargetCore = "serveur_central"

// Frame représente une trame ducky-network.
//
// Le format est ligne à ligne : code, destination, clé de session, utilisateur,
// identifiant machine, puis le contenu — qui peut lui-même tenir sur plusieurs
// lignes.
type Frame struct {
	Code      string
	Target    string
	Session   string
	Username  string
	ClientID  string
	Content   string
	RawFields []string
}

// Category retourne les deux premiers chiffres du code.
//
// C'est sur elle que le splitter décide s'il traite la trame lui-même ou s'il la
// délègue.
func (f Frame) Category() string {
	if len(f.Code) < 2 {
		return ""
	}
	return f.Code[:2]
}

// ContentLines découpe le contenu, les lignes vides de fin retirées.
//
// Presque tous les handlers commencent par là : le faire ici évite que chacun
// réinvente son découpage, et surtout qu'ils divergent sur le traitement d'un
// saut de ligne final.
func (f Frame) ContentLines() []string {
	trimmed := strings.TrimRight(f.Content, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// Line retourne la n-ième ligne de contenu, ou la chaîne vide.
func (f Frame) Line(n int) string {
	lines := f.ContentLines()
	if n < 0 || n >= len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[n])
}

// Build sérialise une trame.
func (f Frame) Build() string {
	return strings.Join([]string{f.Code, f.Target, f.Session, f.Username, f.ClientID, f.Content}, "\n")
}

// ParseFrame lit une trame reçue.
//
// Les réponses du serveur n'ont que trois champs d'en-tête — code, destination,
// clé de session — là où les trames montantes en ont cinq. Le SDK accepte les
// deux formes et ne remplit Username et ClientID que lorsqu'ils sont présents :
// exiger cinq champs ferait échouer la lecture de toutes les réponses.
func ParseFrame(payload string) (Frame, error) {
	lines := strings.Split(payload, "\n")
	if len(lines) < 3 {
		return Frame{}, fmt.Errorf("trame invalide : %d champ(s)", len(lines))
	}
	f := Frame{
		Code:      strings.TrimSpace(lines[0]),
		Target:    strings.TrimSpace(lines[1]),
		Session:   lines[2],
		RawFields: lines,
	}
	if len(lines) > 3 {
		f.Content = strings.Join(lines[3:], "\n")
	}
	return f, nil
}
