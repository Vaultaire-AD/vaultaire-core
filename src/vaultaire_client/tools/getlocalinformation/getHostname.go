package getlocalinformation

import (
	"fmt"
	"os"
)

func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Erreur en récupérant le hostname:", err)
		return ""
	}
	return hostname
}
