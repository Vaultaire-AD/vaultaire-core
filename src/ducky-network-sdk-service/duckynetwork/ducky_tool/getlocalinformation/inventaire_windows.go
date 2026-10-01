//go:build windows

// L'inventaire d'un poste Windows : système, mémoire, processeurs, sessions.
//
// # Pourquoi des API et non des commandes
//
// Le pendant UNIX de ce fichier lance `cat /etc/os-release`, `free -h`, `nproc`
// et `who`. Aucun de ces programmes n'existe sous Windows, et leurs équivalents
// (`wmic`, `systeminfo`, `query user`) sont à éviter pour trois raisons :
//
//   - `wmic` est retiré des versions récentes de Windows ;
//   - leur sortie est TRADUITE — analyser « Mémoire physique totale » marche
//     sur un Windows français et échoue partout ailleurs ;
//   - lancer un processus depuis un service qui tourne en SYSTEM, à chaque
//     inventaire, pour lire trois nombres, se paye en démarrages de processus
//     et en surface d'attaque.
//
// Les API rendent les mêmes valeurs, en une poignée de microsecondes, dans la
// même langue partout.
package getlocalinformation

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procActiveProcessorCount = kernel32.NewProc("GetActiveProcessorCount")

	wtsapi32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW       = wtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSQuerySessionInformationW = wtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsapi32.NewProc("WTSFreeMemory")

	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	procRtlGetVersion = ntdll.NewProc("RtlGetVersion")
)

// --- Système -----------------------------------------------------------------

// osVersionInfoEx est RTL_OSVERSIONINFOEXW.
type osVersionInfoEx struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

// premiereBuildWindows11 : le numéro de build à partir duquel Windows s'appelle
// 11.
//
// Le registre, lui, continue d'annoncer « Windows 10 Pro » sur un Windows 11 :
// Microsoft n'a jamais changé ProductName, pour ne pas casser les programmes
// qui le lisaient. C'est le piège classique de cette collecte — un parc entier
// annoncé en Windows 10 alors qu'il est en 11.
const premiereBuildWindows11 = 22000

// GetOS rend le système, sa version commerciale et son numéro de build.
//
//	Windows 11 Pro 24H2 (build 26100)
//
// Trois sources, parce qu'aucune ne suffit :
//
//   - RtlGetVersion donne le vrai numéro de build. GetVersionEx, lui, MENT :
//     sans manifeste de compatibilité, il rend 6.2 (Windows 8) sur tout système
//     plus récent — un piège hérité de la compatibilité applicative ;
//   - le registre donne l'édition (« Pro », « Entreprise ») et la version
//     commerciale (« 24H2 »), que l'API ne connaît pas ;
//   - le numéro de build tranche entre 10 et 11, que le registre confond.
func GetOS() (string, error) {
	var info osVersionInfoEx
	info.OSVersionInfoSize = uint32(unsafe.Sizeof(info))
	// RtlGetVersion rend un NTSTATUS ; 0 vaut succès. Il ne peut pratiquement
	// pas échouer, mais on ne devine pas une version.
	if r, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&info))); r != 0 {
		return "", fmt.Errorf("RtlGetVersion : code %d", r)
	}

	produit, edition, affichage := lireRegistreVersion()

	nom := produit
	if nom == "" {
		// ProductName absent : on reconstruit un nom, et c'est le seul cas où
		// l'édition du registre sert. Elle n'est PAS ajoutée à un ProductName
		// existant : celui-ci la porte déjà, sous un autre mot — « Windows 10
		// Pro » pour l'édition « Professional ». Les coller donnait « Windows
		// 10 Pro Professional ».
		nom = fmt.Sprintf("Windows %d.%d", info.MajorVersion, info.MinorVersion)
		if edition != "" {
			nom += " " + edition
		}
	}
	// La correction du mensonge du registre.
	if info.MajorVersion >= 10 && info.BuildNumber >= premiereBuildWindows11 {
		nom = strings.Replace(nom, "Windows 10", "Windows 11", 1)
	}
	if affichage != "" {
		nom += " " + affichage
	}
	return fmt.Sprintf("%s (build %d)", strings.TrimSpace(nom), info.BuildNumber), nil
}

// lireRegistreVersion rend (ProductName, EditionID, DisplayVersion).
//
// Une lecture qui échoue n'est PAS une erreur : l'appelant a déjà un nom
// utilisable grâce à RtlGetVersion. Un inventaire incomplet vaut mieux qu'un
// inventaire absent.
func lireRegistreVersion() (string, string, string) {
	cle, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", "", ""
	}
	defer func() { _ = cle.Close() }()

	produit, _, _ := cle.GetStringValue("ProductName")
	edition, _, _ := cle.GetStringValue("EditionID")
	// DisplayVersion (« 24H2 ») a remplacé ReleaseId (« 2009 ») à partir de
	// Windows 10 20H2 : on prend la première qui existe.
	affichage, _, err := cle.GetStringValue("DisplayVersion")
	if err != nil {
		affichage, _, _ = cle.GetStringValue("ReleaseId")
	}
	return produit, edition, affichage
}

// --- Mémoire -----------------------------------------------------------------

// memoryStatusEx est MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// GetRAM rend « totale/utilisée », dans le format de l'inventaire.
//
//	15Gi/7,2Gi
//
// Le MÊME format que la version UNIX, qui reprend celui de `free -h` : le core
// range les deux dans la même colonne, et un format par système rendrait la
// colonne illisible d'un poste à l'autre.
func GetRAM() (string, error) {
	var etat memoryStatusEx
	etat.Length = uint32(unsafe.Sizeof(etat))
	if r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&etat))); r == 0 {
		return "", fmt.Errorf("GlobalMemoryStatusEx : %v", err)
	}
	utilisee := etat.TotalPhys - etat.AvailPhys
	return FormatOctets(etat.TotalPhys) + "/" + FormatOctets(utilisee), nil
}

// --- Processeurs -------------------------------------------------------------

// tousLesGroupes vaut ALL_PROCESSOR_GROUPS.
const tousLesGroupes = 0xFFFF

// GetCPUCount rend le nombre de processeurs logiques.
//
// GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) et non runtime.NumCPU : au-delà
// de 64 processeurs logiques, Windows les range en GROUPES, et un processus ne
// voit par défaut que le sien. Un serveur bi-socket serait annoncé avec la
// moitié de ses cœurs — une valeur fausse qui a l'air juste.
func GetCPUCount() (string, error) {
	n, _, err := procActiveProcessorCount.Call(uintptr(tousLesGroupes))
	if n == 0 {
		return "0", fmt.Errorf("GetActiveProcessorCount : %v", err)
	}
	return fmt.Sprintf("%d", n), nil
}

// --- Sessions ouvertes -------------------------------------------------------

// wtsSessionInfo est WTS_SESSION_INFOW.
type wtsSessionInfo struct {
	SessionID      uint32
	WinStationName *uint16
	State          uint32
}

const (
	wtsActive         = 0 // WTSActive : une session ouverte, connectée
	wtsDisconnected   = 4 // WTSDisconnected : ouverte, mais l'écran est ailleurs
	wtsUserName       = 5 // WTSUserName
	serveurCourantWTS = 0 // WTS_CURRENT_SERVER_HANDLE
)

// GetActiveUsers rend les comptes ayant une session ouverte sur CE poste.
//
// L'équivalent de `who` sous UNIX. Les sessions DÉCONNECTÉES comptent aussi :
// un utilisateur dont la session est verrouillée ou reprise ailleurs est bel et
// bien connecté à la machine, et ses programmes y tournent. Les ignorer ferait
// disparaître du core des sessions qui existent.
//
// Une erreur n'est jamais fatale pour l'inventaire : l'appelant ignore le
// second retour et envoie une liste vide.
func GetActiveUsers() ([]string, error) {
	// Pointeurs TYPÉS plutôt qu'uintptr : l'API rend un tableau alloué par
	// Windows, et le parcourir par arithmétique sur un uintptr est précisément
	// ce que « go vet » signale — à raison. Entre la conversion en uintptr et
	// son usage, le ramasse-miettes a le droit de déplacer ce qu'il gère ; ici
	// la mémoire vient de Windows, mais la règle vaut mieux que l'exception,
	// et unsafe.Slice dit ce qu'on fait.
	var sessions *wtsSessionInfo
	var nombre uint32

	r, _, err := procWTSEnumerateSessionsW.Call(
		uintptr(serveurCourantWTS), 0, 1,
		uintptr(unsafe.Pointer(&sessions)), uintptr(unsafe.Pointer(&nombre)))
	if r == 0 || sessions == nil {
		return nil, fmt.Errorf("WTSEnumerateSessions : %v", err)
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(sessions)))

	var comptes []string
	vus := map[string]bool{}
	for _, info := range unsafe.Slice(sessions, nombre) {
		if info.State != wtsActive && info.State != wtsDisconnected {
			continue
		}
		nom := nomDeSession(info.SessionID)
		// La session 0 est celle des SERVICES : elle n'a pas d'utilisateur, et
		// le compte SYSTEM n'a rien à faire dans une liste de sessions
		// ouvertes.
		if nom == "" || vus[nom] {
			continue
		}
		vus[nom] = true
		comptes = append(comptes, nom)
	}
	return comptes, nil
}

func nomDeSession(session uint32) string {
	var tampon *uint16
	var octets uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(
		uintptr(serveurCourantWTS), uintptr(session), uintptr(wtsUserName),
		uintptr(unsafe.Pointer(&tampon)), uintptr(unsafe.Pointer(&octets)))
	if r == 0 || tampon == nil {
		return ""
	}
	defer procWTSFreeMemory.Call(uintptr(unsafe.Pointer(tampon)))
	return strings.TrimSpace(windows.UTF16PtrToString(tampon))
}
