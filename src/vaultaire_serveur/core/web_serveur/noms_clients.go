package webserveur

import "vaultaire/core/storage"

// NomsDesClients rend, pour chaque machine, son nom d'hôte — TO-DO 191.
//
// Le portail faisait choisir les clients d'un groupe par leur seul identifiant
// unique : une chaîne que personne ne reconnaît. Le gabarit affiche désormais
// « nom — identifiant » ; l'identifiant reste la valeur envoyée, et il reste à
// l'écran, parce que deux machines peuvent porter le même nom.
//
// Une machine sans nom connu (inventaire jamais reçu) n'a pas d'entrée : le
// gabarit montre alors l'identifiant seul, comme avant.
func NomsDesClients(clients []storage.GetClientsByPermission) map[string]string {
	noms := make(map[string]string, len(clients))
	for _, c := range clients {
		if c.Hostname != "" {
			noms[c.ComputeurID] = c.Hostname
		}
	}
	return noms
}
