//go:build windows

package compte

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

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

	advapi32      = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUser = advapi32.NewProc("LogonUserW")
)

// La vérification du secret (LogonUserW) et le masquage du compte.
const (
	logon32LogonNetwork     = 3    // LOGON32_LOGON_NETWORK : vérifier, sans ouvrir de session
	logon32ProviderDefault  = 0    // LOGON32_PROVIDER_DEFAULT
	erreurMauvaisMotDePasse = 1326 // ERROR_LOGON_FAILURE

	cleComptesMasques = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
)

// Indicateurs d'un compte, tels que les attend USER_INFO_1.
const (
	usrPrivUser        = 1       // utilisateur ordinaire, jamais administrateur d'office
	ufScript           = 0x0001  // exigé par NetUserAdd, sans quoi l'appel échoue
	ufDontExpirePasswd = 0x10000 // le mot de passe local ne périme pas
	ufPasswdCantChange = 0x0040  // l'utilisateur ne peut pas changer le mot de passe (TO-DO 195)
	niveauDrapeaux     = 1008    // USER_INFO_1008 : les drapeaux seuls
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

// userInfo1008 porte les drapeaux seuls.
type userInfo1008 struct {
	Flags uint32
}

// localgroupMembersInfo0 désigne un membre par son SID.
type localgroupMembersInfo0 struct {
	SID *windows.SID
}

// Provisionner garantit qu'un compte local existe, ouvert par le secret de
// l'agent, et rend son nom et ce secret (TO-DO 195).
//
// # L'ordre des gestes, et pourquoi
//
//  1. le secret : relu, ou tiré et GARDÉ avant tout — un compte créé avec un
//     mot de passe que l'agent n'aurait pas su garder serait fermé à tous ;
//  2. le compte : créé s'il manque ; s'il existe, son mot de passe n'est posé
//     que si le secret ne l'ouvre pas (voir decider) ;
//  3. le changement de mot de passe interdit à l'utilisateur, et le compte
//     masqué de l'écran d'accueil ;
//  4. le groupe Utilisateurs — sans quoi il n'a pas le droit d'ouvrir une
//     session interactive ;
//  5. Administrateurs si, et seulement si, le core l'a dit.
//
// Le mot de passe du DOMAINE n'entre plus ici : il est vérifié par le core, et
// ne sert plus à rien sur le poste.
func Provisionner(utilisateur string, administrateur bool) (string, string, error) {
	nom := NomLocal(utilisateur)

	nomW, err := windows.UTF16PtrFromString(nom)
	if err != nil {
		return "", "", err
	}

	secret, connu, err := LireSecret(nom)
	if err != nil {
		// Illisible : il est perdu. En tirer un autre est la seule issue — le
		// compte sera reposé, et ses secrets DPAPI avec.
		logs.Write_log("WARNING", fmt.Sprintf("compte local %s : %v — un nouveau secret est tiré", nom, err))
		connu = false
	}
	if !connu {
		if secret, err = GenererMotDePasseLocal(); err != nil {
			return "", "", err
		}
		if err := EcrireSecret(nom, secret); err != nil {
			return "", "", fmt.Errorf("compte local %s : secret non gardé, rien n'est touché : %w", nom, err)
		}
	}
	secretW, err := windows.UTF16PtrFromString(secret)
	if err != nil {
		return "", "", err
	}

	existe, err := compteExiste(nomW)
	if err != nil {
		return "", "", err
	}
	var ouvre *bool
	if existe && connu {
		ouvre = secretOuvre(nomW, secretW)
	}

	switch decider(existe, connu, ouvre) {
	case GesteCreer:
		if err := creer(nomW, secretW, utilisateur); err != nil {
			return "", "", fmt.Errorf("compte local %s non créé : %w", nom, err)
		}
		logs.Write_log("INFO", fmt.Sprintf("compte local %s créé pour %s", nom, utilisateur))
	case GestePoser:
		if err := poserMotDePasse(nomW, secretW); err != nil {
			return "", "", fmt.Errorf("mot de passe du compte local %s non posé : %w", nom, err)
		}
		pourquoi := "il portait encore le mot de passe du domaine (compte d'avant le TO-DO 195)"
		if connu {
			pourquoi = "le secret de l'agent ne l'ouvrait plus (mot de passe changé hors de Vaultaire)"
		}
		logs.Write_log("WARNING", fmt.Sprintf("compte local %s : mot de passe remplacé par le secret de "+
			"l'agent — %s. Les secrets Windows de ce compte (mots de passe enregistrés) sont perdus",
			nom, pourquoi))
	}

	// Non bloquants : la session s'ouvre sans eux. Mais l'interdiction de
	// changer le mot de passe est ce qui empêche un utilisateur de s'en donner
	// un qu'il connaîtrait — donc de rouvrir la porte du 195 — : son échec est
	// un AVERTISSEMENT, et il est retenté à chaque connexion.
	if err := interdireLeChangement(nomW); err != nil {
		logs.Write_log("WARNING", fmt.Sprintf("compte local %s : changement de mot de passe non interdit : %v", nom, err))
	}
	if err := masquerDeLAccueil(nom); err != nil {
		logs.Write_log("WARNING", fmt.Sprintf("compte local %s : non masqué de l'écran d'accueil : %v", nom, err))
	}

	// Utilisateurs : sans ce groupe, la session interactive est refusée par
	// Windows lui-même, APRÈS que le mot de passe a été accepté — le pire des
	// symptômes, puisque tout semble juste.
	if err := ajouterAuGroupe(sidUtilisateurs, nomW); err != nil {
		return nom, "", fmt.Errorf("compte local %s non inscrit dans Utilisateurs : %w", nom, err)
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

	return nom, secret, nil
}

// secretOuvre essaie le secret contre le compte, par une ouverture RÉSEAU —
// sans session, sans profil chargé.
//
// Rend faux seulement sur ERROR_LOGON_FAILURE (mauvais mot de passe). Tout
// autre refus — droit d'accès réseau retiré par la stratégie, compte
// verrouillé ou désactivé — vient APRÈS la vérification du mot de passe, ou ne
// dit rien de lui : nil, « je ne sais pas », et rien n'est reposé.
func secretOuvre(nomW, secretW *uint16) *bool {
	point, _ := windows.UTF16PtrFromString(".")
	var jeton windows.Handle
	r, _, e := procLogonUser.Call(uintptr(unsafe.Pointer(nomW)), uintptr(unsafe.Pointer(point)),
		uintptr(unsafe.Pointer(secretW)), logon32LogonNetwork, logon32ProviderDefault,
		uintptr(unsafe.Pointer(&jeton)))
	if r != 0 {
		_ = windows.CloseHandle(jeton)
		vrai := true
		return &vrai
	}
	if errno, ok := e.(syscall.Errno); ok && uintptr(errno) == erreurMauvaisMotDePasse {
		faux := false
		return &faux
	}
	logs.Write_log("DEBUG", fmt.Sprintf("vérification du secret non concluante (%v) : rien n'est reposé", e))
	return nil
}

// interdireLeChangement pose « l'utilisateur ne peut pas changer le mot de
// passe » et « n'expire jamais » sur un compte existant.
func interdireLeChangement(nomW *uint16) error {
	var tampon *byte
	if err := windows.NetUserGetInfo(nil, nomW, niveauUtilisateur1, &tampon); err != nil {
		return err
	}
	drapeaux := (*userInfo1)(unsafe.Pointer(tampon)).Flags
	_ = windows.NetApiBufferFree(tampon)
	voulus := drapeaux | ufPasswdCantChange | ufDontExpirePasswd
	if voulus == drapeaux {
		return nil
	}
	info := userInfo1008{Flags: voulus}
	var erreurParam uint32
	r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(nomW)), niveauDrapeaux,
		uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&erreurParam)))
	if r != 0 {
		return ErreurNetapi("NetUserSetInfo(1008)", uint32(r), erreurParam)
	}
	return nil
}

// masquerDeLAccueil retire le compte de la liste des comptes de l'écran
// d'accueil (SpecialAccounts\UserList, valeur 0) : sa tuile Windows ne mène
// nulle part, l'utilisateur passe par celle de Vaultaire.
func masquerDeLAccueil(nom string) error {
	cle, _, err := registry.CreateKey(registry.LOCAL_MACHINE, cleComptesMasques, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer cle.Close()
	if v, _, err := cle.GetIntegerValue(nom); err == nil && v == 0 {
		return nil
	}
	return cle.SetDWordValue(nom, 0)
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
		Flags: ufScript | ufNormalAccount | ufDontExpirePasswd | ufPasswdCantChange,
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
