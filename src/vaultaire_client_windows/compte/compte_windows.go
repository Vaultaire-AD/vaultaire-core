//go:build windows

package compte

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Les appels de netapi32.
//
// x/sys/windows ne déclare que la lecture (NetUserGetInfo) : l'écriture est
// posée ici. LazyDLL plutôt que //go:linkname ou cgo — la DLL est présente sur
// toute installation de Windows, et l'absence d'un symbole se voit au premier
// appel avec un message clair.
var (
	netapi32                  = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd            = netapi32.NewProc("NetUserAdd")
	procNetUserSetInfo        = netapi32.NewProc("NetUserSetInfo")
	procNetLocalGroupAddMembs = netapi32.NewProc("NetLocalGroupAddMembers")
)

// Indicateurs d'un compte, tels que les attend USER_INFO_1.
const (
	usrPrivUser        = 1       // utilisateur ordinaire, jamais administrateur d'office
	ufScript           = 0x0001  // exigé par NetUserAdd, sans quoi l'appel échoue
	ufDontExpirePasswd = 0x10000 // le mot de passe local ne périme pas
	ufNormalAccount    = 0x0200  // compte ordinaire
	niveauUtilisateur1 = 1       // USER_INFO_1
	niveauMotDePasse   = 1003    // USER_INFO_1003 : le mot de passe seul
	niveauMembreParSID = 0       // LOCALGROUP_MEMBERS_INFO_0 : membre désigné par SID
	erreurMembreExiste = 1378    // ERROR_MEMBER_IN_ALIAS
)

// Les codes de netapi32 et leur traduction vivent dans erreurs.go, qui compile
// sur toute plateforme : un message d'erreur ne se vérifie qu'en le lisant, et
// il ne fallait pas une machine Windows pour cela.
const (
	erreurCompteExiste  = ErrCompteExiste
	erreurCompteInconnu = ErrCompteInconnu
)

// SID des groupes locaux, plutôt que leurs noms.
//
// Le nom d'un groupe intégré est TRADUIT : « Users » sur un Windows anglais,
// « Utilisateurs » sur un français, autre chose ailleurs. Un nom écrit en dur
// marche sur la machine de développement et échoue sur le parc, avec un code
// numérique pour seule explication. Le SID, lui, est le même partout.
var (
	sidUtilisateurs   = "S-1-5-32-545" // Utilisateurs
	sidAdministrateur = "S-1-5-32-544" // Administrateurs
)

// userInfo1 est USER_INFO_1, dans l'ordre exact de la structure Win32.
type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

// userInfo1003 porte un mot de passe seul (changement).
type userInfo1003 struct {
	Password *uint16
}

// localgroupMembersInfo0 désigne un membre par son SID.
type localgroupMembersInfo0 struct {
	SID *windows.SID
}

// Provisionner garantit qu'un compte local existe avec CE mot de passe.
//
// Rend le nom du compte local à utiliser pour ouvrir la session.
//
// # L'ordre des gestes, et pourquoi
//
//  1. créer le compte s'il manque, ou lui poser le mot de passe s'il existe ;
//  2. l'inscrire dans le groupe Utilisateurs — sans quoi il n'a pas le droit
//     d'ouvrir une session interactive ;
//  3. l'inscrire dans Administrateurs si, et seulement si, le core l'a dit.
//
// Le mot de passe est posé à CHAQUE connexion réussie, et non seulement à la
// création : c'est ce qui fait suivre au compte local un changement de mot de
// passe côté domaine. Sans cela, l'utilisateur changerait son mot de passe dans
// le portail et continuerait d'entrer sur le poste avec l'ancien.
func Provisionner(utilisateur, motDePasse string, administrateur bool) (string, error) {
	nom := NomLocal(utilisateur)

	nomW, err := windows.UTF16PtrFromString(nom)
	if err != nil {
		return "", err
	}
	mdpW, err := windows.UTF16PtrFromString(motDePasse)
	if err != nil {
		return "", err
	}

	existe, err := compteExiste(nomW)
	if err != nil {
		return "", err
	}

	if existe {
		if err := poserMotDePasse(nomW, mdpW); err != nil {
			return "", fmt.Errorf("mot de passe du compte local %s non mis à jour : %w", nom, err)
		}
		logs.Write_log("INFO", fmt.Sprintf("compte local %s : mot de passe aligné sur le domaine", nom))
	} else {
		if err := creer(nomW, mdpW, utilisateur); err != nil {
			return "", fmt.Errorf("compte local %s non créé : %w", nom, err)
		}
		logs.Write_log("INFO", fmt.Sprintf("compte local %s créé pour %s", nom, utilisateur))
	}

	// Utilisateurs : sans ce groupe, la session interactive est refusée par
	// Windows lui-même, APRÈS que le mot de passe a été accepté — le pire des
	// symptômes, puisque tout semble juste.
	if err := ajouterAuGroupe(sidUtilisateurs, nomW); err != nil {
		return nom, fmt.Errorf("compte local %s non inscrit dans Utilisateurs : %w", nom, err)
	}

	if administrateur {
		if err := ajouterAuGroupe(sidAdministrateur, nomW); err != nil {
			// NON bloquant : l'utilisateur a le droit d'entrer, il entrera sans
			// ses privilèges. Refuser la session pour un groupe non posé
			// laisserait dehors quelqu'un que le core vient d'accepter.
			logs.Write_log("WARNING", fmt.Sprintf(
				"compte local %s non inscrit dans Administrateurs : %v", nom, err))
		}
	}

	return nom, nil
}

func compteExiste(nomW *uint16) (bool, error) {
	var tampon *byte
	err := windows.NetUserGetInfo(nil, nomW, niveauUtilisateur1, &tampon)
	if err == nil {
		_ = windows.NetApiBufferFree(tampon)
		return true, nil
	}
	if errno, ok := err.(syscall.Errno); ok && uintptr(errno) == erreurCompteInconnu {
		return false, nil
	}
	return false, fmt.Errorf("lecture du compte local impossible : %w", err)
}

func creer(nomW, mdpW *uint16, utilisateur string) error {
	commentaire, err := windows.UTF16PtrFromString(Commentaire)
	if err != nil {
		return err
	}
	info := userInfo1{
		Name:     nomW,
		Password: mdpW,
		Priv:     usrPrivUser,
		Comment:  commentaire,
		// UF_SCRIPT est EXIGÉ par NetUserAdd : sans lui, l'appel rend
		// ERROR_INVALID_PARAMETER, et rien ne dit lequel.
		Flags: ufScript | ufNormalAccount | ufDontExpirePasswd,
	}
	var erreurParam uint32
	r, _, _ := procNetUserAdd.Call(0, niveauUtilisateur1,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&erreurParam)))
	if r != 0 {
		if r == erreurCompteExiste {
			// Course avec une autre session : quelqu'un vient de le créer.
			return poserMotDePasse(nomW, mdpW)
		}
		return ErreurNetapi("NetUserAdd", uint32(r), erreurParam)
	}
	_ = utilisateur // le nom complet du domaine n'est pas posé en V1 : voir README
	return nil
}

func poserMotDePasse(nomW, mdpW *uint16) error {
	info := userInfo1003{Password: mdpW}
	var erreurParam uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(nomW)), niveauMotDePasse,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&erreurParam)))
	if r != 0 {
		return ErreurNetapi("NetUserSetInfo", uint32(r), erreurParam)
	}
	return nil
}

func ajouterAuGroupe(sidGroupe string, nomW *uint16) error {
	groupe, err := nomDuGroupe(sidGroupe)
	if err != nil {
		return err
	}
	groupeW, err := windows.UTF16PtrFromString(groupe)
	if err != nil {
		return err
	}
	sidCompte, _, _, err := windows.LookupSID("", windows.UTF16PtrToString(nomW))
	if err != nil {
		return fmt.Errorf("SID du compte local introuvable : %w", err)
	}
	membre := localgroupMembersInfo0{SID: sidCompte}
	r, _, _ := procNetLocalGroupAddMembs.Call(0, uintptr(unsafe.Pointer(groupeW)),
		niveauMembreParSID, uintptr(unsafe.Pointer(&membre)), 1)
	if r != 0 && r != erreurMembreExiste {
		return fmt.Errorf("NetLocalGroupAddMembers(%s) : code %d", groupe, r)
	}
	return nil
}

// nomDuGroupe traduit un SID intégré en son nom sur CETTE machine.
func nomDuGroupe(sid string) (string, error) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return "", err
	}
	nom, _, _, err := s.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("groupe %s introuvable : %w", sid, err)
	}
	return nom, nil
}
