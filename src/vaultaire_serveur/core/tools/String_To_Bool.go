package tools

func String_tobool_yesnot(a string) bool {
	switch a {
	case "yes":
		return true
	case "not":
		return false
	default:
		return false // Stoppe l'exécution en cas d'échec
	}
}
