package networksecurity

var ExpectedTrames = []string{"01_01", "02_01", "02_03"}

// HostTrames : ordre autorisé pour un client de type host (proxy, etc.) après 01_01
var HostTrames = []string{"04_01", "04_03", "04_05", "04_07"}

// Vérifie si une trame suit bien l'ordre défini
func IsValidNextTrame(lastTrame string, newTrame string) bool {
	// Cas spécial : première trame
	if lastTrame == "" && newTrame == ExpectedTrames[0] {
		return true
	}
	for i, t := range ExpectedTrames {
		if t == lastTrame && i+1 < len(ExpectedTrames) && ExpectedTrames[i+1] == newTrame {
			return true
		}
	}
	// Chemin host : après 01_01 on accepte 04_01 (register_host)
	if lastTrame == "01_01" && newTrame == "04_01" {
		return true
	}
	// Après 04_01, le host peut envoyer 04_03, 04_05, 04_07 (et répéter)
	if lastTrame == "04_01" || lastTrame == "04_03" || lastTrame == "04_05" || lastTrame == "04_07" {
		for _, ht := range HostTrames {
			if ht == newTrame {
				return true
			}
		}
	}
	return false
}
