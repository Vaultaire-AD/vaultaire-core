package display

import (
	"fmt"
	"log"
	"strings"
	"text/tabwriter"
	"vaultaire/core/logs"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

func DisplayAllClientPermissions(permissions []storage.ClientPermission) string {
	// Créer un StringBuilder pour accumuler le contenu
	var sb strings.Builder

	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	header := color.New(color.FgYellow, color.Bold).SprintFunc()

	// Ajouter le titre
	sb.WriteString(title("🔑 Liste de toutes les Permissions Client") + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Créer un tableau formaté avec tabwriter
	w := tabwriter.NewWriter(&sb, 0, 8, 1, ' ', 0)

	// Ajouter les en-têtes
	_, err := fmt.Fprintf(w, "%-15s %-25s %-25s\n",
		header("ID Permission Client"),
		header("Nom de la Permission Client"),
		header("Admin"),
	)
	if err != nil {
		logs.Write_Log("ERROR", "Erreur lors de l'écriture des en-têtes: "+err.Error())
		return "Erreur lors de l'affichage des permissions."
	}

	// Ajouter chaque permission client
	for _, permission := range permissions {
		_, err := fmt.Fprintf(w, "%-15d %-25s %-15t\n",
			permission.ID,
			permission.Name,
			permission.IsAdmin,
		)
		if err != nil {
			logs.Write_Log("ERROR", "Erreur lors de l'écriture du tableau: "+err.Error())
			return "Erreur lors de l'affichage des permissions."
		}
	}

	// Vider le tampon pour s'assurer que tout est écrit dans sb
	err = w.Flush()
	if err != nil {
		log.Printf("Erreur lors de l'écriture du tableau: %v\n", err)
		return "Erreur lors de l'affichage des permissions."
	}

	// Ajouter une ligne de séparation
	sb.WriteString("--------------------------------------------------\n")

	return sb.String()
}
