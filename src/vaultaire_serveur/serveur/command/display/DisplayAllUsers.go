package display

import (
	"DUCKY/serveur/storage"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

func DisplayAllUsers(users []storage.GetUsers) string {
	// Créer un StringBuilder pour accumuler le contenu
	var sb strings.Builder

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Ajouter le titre
	sb.WriteString(title("👥 Liste de tous les Utilisateurs") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	fmt.Fprintf(w, "%-15s %-25s %-15s %-20s\n",
		header("ID Utilisateur"),
		header("Username"),
		header("Date de Naissance"),
		header("Créé à"),
	)

	// Ajouter chaque utilisateur
	for _, user := range users {
		// Format de la date de naissance (si elle existe)
		dateNaissance := user.DateNaissance

		// Ajouter les détails de l'utilisateur
		fmt.Fprintf(w, "%-15d %-25s %-15s %-20s\n",
			user.ID,
			user.Username,
			dateNaissance,
			user.CreatedAt,
		)
	}

	// Vider le tampon pour s'assurer que tout est écrit dans sb
	w.Flush()

	// Ajouter une ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	// Retourner le contenu accumulé sous forme de chaîne
	return sb.String()
}
