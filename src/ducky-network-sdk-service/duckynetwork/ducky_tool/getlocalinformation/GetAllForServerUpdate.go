package getlocalinformation

import (
	"strings"

	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/version"
)

// GetAllLocalInfForServeur compose l'inventaire envoyé au core (trame 02_12).
//
//	hostname\nos\nram\nprocesseur
//
// Les VERSIONS ne sont pas ici : elles se placent APRÈS la liste des sessions
// actives, que l'appelant ajoute. Voir VersionsPourInventaire.
func GetAllLocalInfForServeur() string {
	hostname := GetHostname()
	ram, _ := GetRAM()
	processeur, _ := GetCPUCount()
	os, _ := GetOS()

	return ComposerMateriel(hostname, os, ram, processeur)
}

// ComposerMateriel assemble les quatre premières lignes de l'inventaire.
//
// Chaque valeur tient sur UNE ligne, quoi qu'en disent les commandes qui la
// produisent : la trame est positionnelle, et un seul retour à la ligne en
// trop décale tout ce qui suit. C'est arrivé avec `nproc` (TO-DO 214) — la
// version de l'agent était lue dans la liste des sessions. Le garde-fou est
// ici, à l'assemblage, et non dans chaque commande : la prochaine commande
// oubliée ne décalera rien non plus.
func ComposerMateriel(hostname, os, ram, processeur string) string {
	return UneLigne(hostname) + "\n" + UneLigne(os) + "\n" + UneLigne(ram) + "\n" + UneLigne(processeur)
}

// UneLigne ramène une valeur de l'inventaire sur une seule ligne : espaces de
// bord retirés, retours à la ligne intérieurs remplacés par une espace.
func UneLigne(v string) string {
	v = strings.TrimSpace(v)
	return strings.Join(strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == '\r' }), " ")
}

// VersionsPourInventaire rend les deux lignes de version de la trame 02_12.
//
//	<version du programme>\n<version du socle réseau>
//
// # Pourquoi en QUEUE de la trame
//
// L'inventaire comptait cinq lignes — matériel, puis sessions actives. Insérer
// les versions au milieu ferait lire les sessions comme une version par tout
// core resté à l'ancienne version, et inversement.
//
// En queue, un core ancien ignore simplement ce qu'il ne lit pas, et un core
// à jour distingue « absent » de « vide ». Même arbitrage que le port et
// l'empreinte dans 04_01.
//
// # Deux valeurs et non une
//
// L'agent et le socle ne bougent pas ensemble. C'est précisément la question
// que pose le point 39 : quel programme, et construit avec quel SDK.
// # Une ligne vide plutôt qu'une ligne absente
//
// Un binaire qui n'a pas posé sa version envoie une ligne VIDE. L'omettre
// décalerait le champ suivant, et le core lirait la version du socle comme
// celle du programme — une valeur fausse qui a l'air juste, ce qui est pire
// qu'une valeur manquante.
func VersionsPourInventaire() string {
	return UneLigne(storage.VersionComposant) + "\n" + UneLigne(version.SDK().Complete())
}
