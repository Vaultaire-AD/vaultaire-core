package dbgroups

// Fonction utilitaire pour transformer une string en slice
func splitIfNotEmpty(s string) []string {
	if s == "" {
		return []string{}
	}
	return splitTrim(s, ", ")
}
