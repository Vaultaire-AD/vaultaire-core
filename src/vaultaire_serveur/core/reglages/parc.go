package reglages

import "vaultaire/core/parcversion"

// Ce que la cadence de vérification en ligne exige du parc (TO-DO 161).
//
// # Le défaut que le 110 a laissé derrière lui
//
// Depuis la 2.2, le core annonce sa cadence dans la 02_11 (« online:<n> »), et
// un agent à jour règle sur elle le délai après lequel il ferme un tunnel
// muet. Un agent ANTÉRIEUR ne lit pas cette ligne : il garde son délai fixe de
// dix minutes. Or, entre deux cycles de GPO, la 02_11 est le seul trafic d'un
// tunnel. À une cadence de dix minutes ou plus, cet agent ferme donc son tunnel
// entre deux battements et se reconnecte — en boucle, le symptôme même que le
// 110 avait retiré pour les autres.
//
// # Pourquoi 8 et non 9
//
// À 9 minutes, la 02_11 arrive avant les dix minutes du délai — sur le papier.
// Mais le core l'envoie machine par machine, dans un tour qui prend du temps sur
// un grand parc, et une 02_11 perdue double le silence. Deux minutes de marge :
// c'est la valeur que la Consequence du réglage conseille depuis la 2.2, et
// elle est tirée de cette constante pour que le conseil et le contrôle ne
// puissent pas diverger.
const CadenceSurePourAgentsAnterieurs = 8

// VersionQuiSuitLaCadence est la première version d'agent qui lit « online: ».
var VersionQuiSuitLaCadence = parcversion.V(2, 2, 0)

// ExigeUnParcAJour dit si poser cette valeur sur ce réglage suppose que tout le
// parc suive la cadence annoncée.
//
// Pure : l'action qui l'appelle lit le parc ; ce paquet n'en sait rien.
func ExigeUnParcAJour(cle string, valeur int) bool {
	return cle == CleVerificationEnLigne && valeur > CadenceSurePourAgentsAnterieurs
}
