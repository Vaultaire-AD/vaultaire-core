package display

import (
	"fmt"

	"vaultaire/core/storage"
)

// DisplayUserPublicKeys liste les clés SSH d'un compte.
//
// La clé est tronquée à son début et sa fin : une clé RSA fait plus de sept
// cents caractères et noierait la table, alors que ses extrémités suffisent à
// l'identifier — c'est aussi ce qu'affiche « ssh-add -l ».
//
// L'identifiant est montré parce qu'il sert à la retirer :
// « remove -u <compte> -k <id> ».
func DisplayUserPublicKeys(username string, pubKeys []storage.PublicKey) string {
	if len(pubKeys) == 0 {
		return fmt.Sprintf("Aucune clé publique pour %s.", username)
	}

	t := NouvelleTable("ID", "Libellé", "Clé", "Ajoutée le")
	for _, k := range pubKeys {
		t.Ajouter(
			fmt.Sprintf("%d", k.ID),
			Valeur(k.Label),
			abregerCle(k.Key),
			Valeur(k.CreatedAt),
		)
	}
	return fmt.Sprintf("Clés publiques de %s — %d\n\nRetirer une clé : remove -u %s -k <id>\n\n%s",
		username, len(pubKeys), username, t.String())
}

// abregerCle garde le type, le début et la fin du corps.
func abregerCle(cle string) string {
	const garde = 12
	champs := splitChamps(cle)
	if len(champs) < 2 {
		return Valeur(cle)
	}
	corps := champs[1]
	if len(corps) <= garde*2 {
		return champs[0] + " " + corps
	}
	return champs[0] + " " + corps[:garde] + "…" + corps[len(corps)-garde:]
}

func splitChamps(s string) []string {
	var out []string
	debut := -1
	for i, r := range s {
		if r == ' ' || r == '\t' {
			if debut >= 0 {
				out = append(out, s[debut:i])
				debut = -1
			}
			continue
		}
		if debut < 0 {
			debut = i
		}
	}
	if debut >= 0 {
		out = append(out, s[debut:])
	}
	return out
}
