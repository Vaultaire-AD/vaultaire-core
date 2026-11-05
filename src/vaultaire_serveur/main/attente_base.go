package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

// --attendre-base <secondes> — 2.3, image rootless.
//
// Attend que la base réponde en TCP, puis rend la main. Sert de conteneur
// d'initialisation dans Kubernetes : l'image n'a ni shell ni nc, et un core
// lancé avant sa base échouerait, redémarrerait, et repousserait d'autant la
// mise en service (CrashLoopBackOff). L'adresse vient de VAULTAIRE_DB_HOST et
// VAULTAIRE_DB_PORT (3306 par défaut) ; aucune configuration n'est lue.
func attendreBase(args []string, sortie io.Writer) int {
	delai := 120
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 1 {
			fmt.Fprintf(sortie, "--attendre-base : durée en secondes attendue, reçu %q\n", args[0])
			return 2
		}
		delai = n
	}
	hote := os.Getenv("VAULTAIRE_DB_HOST")
	if hote == "" {
		fmt.Fprintln(sortie, "--attendre-base : VAULTAIRE_DB_HOST n'est pas posée")
		return 2
	}
	port := os.Getenv("VAULTAIRE_DB_PORT")
	if port == "" {
		port = "3306"
	}
	adresse := net.JoinHostPort(hote, port)
	fin := time.Now().Add(time.Duration(delai) * time.Second)
	for essai := 1; ; essai++ {
		c, err := net.DialTimeout("tcp", adresse, 3*time.Second)
		if err == nil {
			c.Close()
			fmt.Fprintf(sortie, "base joignable : %s (essai %d)\n", adresse, essai)
			return 0
		}
		if time.Now().After(fin) {
			fmt.Fprintf(sortie, "base injoignable après %d s : %s : %v\n", delai, adresse, err)
			return 1
		}
		if essai == 1 || essai%10 == 0 {
			fmt.Fprintf(sortie, "en attente de la base %s : %v\n", adresse, err)
		}
		time.Sleep(2 * time.Second)
	}
}
