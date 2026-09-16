package commanddns

import (
	"database/sql"
	"fmt"
	"vaultaire/core/command/display"
	"vaultaire/core/logs"
)

// command_dns_showReverse affiche les enregistrements PTR de la table
// ptr_records.
func command_dns_showReverse(commandList []string, db *sql.DB) string {
	rows, err := db.Query(`SELECT ip, name FROM ptr_records ORDER BY ip ASC`)
	if err != nil {
		return fmt.Sprintf("Erreur lors de la récupération des enregistrements PTR : %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "Fermeture du curseur PTR : "+err.Error())
		}
	}()

	// L'en-tête était écrit à la main — « Adresse IP » suivi d'espaces comptés
	// à l'œil — puis les lignes rendues avec `%-23s`. Deux largeurs à tenir
	// synchronisées manuellement, et la seconde ne tenait pas : une adresse
	// IPv6 dépasse vingt-trois caractères et poussait sa ligne. Le module
	// d'affichage calcule la colonne sur le contenu réel.
	tb := display.NouvelleTable("ADRESSE IP", "NOM")
	for rows.Next() {
		var ip, name string
		if err := rows.Scan(&ip, &name); err != nil {
			return fmt.Sprintf("Erreur de lecture d'une ligne PTR : %v", err)
		}
		tb.Ajouter(ip, display.Valeur(name))
	}

	// rows.Err() après la boucle.
	//
	// `rows.Next()` rend false aussi bien à la fin des données qu'en cas
	// d'erreur d'itération — connexion coupée, lecture interrompue. Sans cette
	// vérification, un jeu de résultats tronqué s'affichait comme un jeu
	// complet : l'utilisateur voyait « 3 enregistrements PTR » là où la base en
	// contenait trente, sans le moindre signe que quelque chose avait échoué.
	if err := rows.Err(); err != nil {
		return fmt.Sprintf("Lecture des enregistrements PTR interrompue : %v — "+
			"la liste ci-dessus serait incomplète, elle n'est donc pas affichée.", err)
	}

	if tb.Vide() {
		return "Aucun enregistrement PTR.\n"
	}
	return "Enregistrements PTR (DNS inverse)\n\n" + tb.String()
}
