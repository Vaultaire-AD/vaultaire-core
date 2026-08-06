package getlocalinformation

import (
	"os/exec"
	"strings"
)

func GetActiveUsers() ([]string, error) {
	cmd := exec.Command("who")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	var users []string
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			users = append(users, fields[0])
		}
	}

	return users, nil
}

//func main() {
//	users, err := getActiveUsers()
//	if err != nil {
//		fmt.Println("Erreur en récupérant les utilisateurs actifs:", err)
//		return
//	}
//	fmt.Println("Utilisateurs actifs:", users)
//}
