package getlocalinformation

func GetAllLocalInfForServeur() string {
	hostname := GetHostname()
	ram, _ := GetRAM()
	processeur, _ := GetCPUCount()
	os, _ := GetOS()

	return hostname + "\n" + os + "\n" + ram + "\n" + processeur
}
