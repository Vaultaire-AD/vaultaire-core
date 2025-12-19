package networksecurity

var ExpectedTrames = []string{"01_01", "02_01", "02_03"}

// Vérifie si une trame suit bien l'ordre défini
func IsValidNextTrame(lastTrame string, newTrame string) bool {
	for i, t := range ExpectedTrames {
		if t == lastTrame && i+1 < len(ExpectedTrames) && ExpectedTrames[i+1] == newTrame {
			return true
		}
	}
	// Cas spécial : première trame
	return lastTrame == "" && newTrame == ExpectedTrames[0]
}
