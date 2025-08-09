package tools

func String_tobool_yesnot(a string) bool {
	var isValid bool
	if a == "yes" {
		isValid = true
	} else if a == "not" {
		isValid = false
	} else {
		return false // Stoppe l'exécution en cas d'échec
	}
	return isValid
}
