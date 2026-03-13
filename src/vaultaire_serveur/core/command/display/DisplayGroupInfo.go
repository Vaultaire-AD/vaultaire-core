package display

import (
	"strings"
	"vaultaire/core/storage"

	"github.com/fatih/color"
)

// DisplayGroupInfo renvoie les informations d'un groupe sous forme de chaîne formatée
func DisplayGroupInfo(group *storage.GroupInfo) string {
	// Configurer les couleurs
	title := color.New(color.FgHiBlue, color.Bold).SprintFunc()
	section := color.New(color.FgGreen, color.Bold).SprintFunc()

	// Utilisation d'un StringBuilder pour accumuler la sortie
	var sb strings.Builder

	// Titre principal avec nom du groupe
	sb.WriteString(title("📂 Group Information: "+group.Name) + "\n")
	sb.WriteString("--------------------------------------------------\n")

	// Affichage du domaine
	sb.WriteString(section("🌐 Domain:") + "\n")
	if group.DomainName != "" {
		sb.WriteString("   - " + group.DomainName + "\n")
	} else {
		sb.WriteString("   ❌ No domain associated with this group.\n")
	}
	sb.WriteString("--------------------------------------------------\n")

	// Utilisateurs dans le groupe
	sb.WriteString(section("👥 Users in Group:") + "\n")
	if len(group.Users) > 0 {
		for _, user := range group.Users {
			sb.WriteString("   - " + user + "\n")
		}
	} else {
		sb.WriteString("   ❌ No users in this group.\n")
	}
	sb.WriteString("--------------------------------------------------\n")

	// Permissions du groupe
	sb.WriteString(section("🔑 Group Permissions:") + "\n")
	if len(group.Permissions) > 0 {
		for _, perm := range group.Permissions {
			sb.WriteString("   - " + perm + "\n")
		}
	} else {
		sb.WriteString("   ❌ No permissions assigned to this group.\n")
	}
	sb.WriteString("--------------------------------------------------\n")

	// Clients associés
	sb.WriteString(section("🖥️ Clients (Softwares) in Group:") + "\n")
	if len(group.Clients) > 0 {
		for _, client := range group.Clients {
			sb.WriteString("   - " + client + "\n")
		}
	} else {
		sb.WriteString("   ❌ No clients associated with this group.\n")
	}
	sb.WriteString("--------------------------------------------------\n")

	// Permissions des clients
	sb.WriteString(section("🔐 Client Permissions:") + "\n")
	if len(group.ClientPerms) > 0 {
		for _, perm := range group.ClientPerms {
			sb.WriteString("   - " + perm + "\n")
		}
	} else {
		sb.WriteString("   ❌ No permissions assigned to clients in this group.\n")
	}
	sb.WriteString("--------------------------------------------------\n")

	// GPOs du groupe
	sb.WriteString(section("🔒 Group GPOs:") + "\n")
	if len(group.GPOs) > 0 {
		for _, gpo := range group.GPOs {
			sb.WriteString("   - " + gpo + "\n")
		}
	} else {
		sb.WriteString("   ❌ No GPOs assigned to this group.\n")
	}
	sb.WriteString("--------------------------------------------------\n")

	return sb.String()
}
