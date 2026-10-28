package paquetagent

import (
	"strings"
	"testing"
)

// Le vecteur jumeau du JEU de clés — TO-DO 207.
//
// LE MÊME FICHIER, octet pour octet sous ses constantes, vit dans
// vaultaire_serveur/core/paquetagent et dans vaultaire_client/paquet : le core
// signe un jeu et écrit le fichier d'une machine, l'agent vérifie ce jeu et
// réécrit son fichier. Si l'un change la composition du corps, l'enveloppe ou
// le texte du fichier sans l'autre, sa suite échoue ici.
//
// Deux clés de TEST (3072 bits), sans autre usage, jeu n°2 signé par la
// première ; les parties privées n'ont pas été conservées.

const corpsJeuReference = "vaultaire-pkg-trust-v1\n2\ncle MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsjXg3RSkLXiGKIe2o7JULc3/LuoeM2FewuRmkr7qJ9zgfjGgg7amWxevZd4nLeNBOjOL91ec2yLmByB7aTMz3otCh8BhNLszPuig8WlbJPJQNkCnoFGzSPrsINMWp/03St34CyyDVUkc2tmyc4sB0haOfrHpUL/sfUS8uVsDLIIm63iQ7HZQrbLz9UBY4b2xPRrA5McvzPEsDgMK0vfQwthzX6nC94ZxspgHeEP/LAYlJ8lCDeqUIi0X+uidsYPdnfr7jT6f4UJOxadoweOC6HyUbeuZqOesEGeYI5QJplQmlzpsNUuPYuQsF4CggwGOKsWUCxlIbetAxUfStyz/QzwkH3luuojqyWNkwesH3WgfYVpthkVW9UWPsZhB70cvGS4HMyjVJ4SgjZbJuXq15wMLmAQ36WIitZdw2Lm0lWL+3sSM7hH+AxlM3Wh3ajtvgIHl5i2WzFyXizIwmaCsR4BI+LoiZotiW/8BKAMJetZRMyPmEghx+lrH/MFdk+3lAgMBAAE=\ncle MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAycGLmlXpy7sFnKXuJF00nlF9BuUuvR+5UTiLOTQasMTCk5w/x6bZ4jTHS8hXXJIZ3f2qRXoE88Y+MewaAI3p1hpqAAv0Oj2F8r6BXcKsxZZEWDytDPCW9eVXAf5Rx/PqdtTXFvk/nINJppgS1NRP69sXy5/RtNHuwVMt8Q+vy9ivCUC/9IowM8IhfuEicGoq9Rb5b5Edazylqx6szv0YFCljTxWZ8KFYNOAnjsSgOWHpyV2YCvh74ingwZtvPKr9YJMQ995Yy0NRuFy/mvIJxG4lVNa36aDFuP+ANlxuRB9GYb5rUDBJphQXf3X/f4rJ0wBguG9oYC9xKfQBh5k+PkdYrzC8otQFbfS/lwxbQoNZlYHrKHoxG6zFofupwQLOSRgH2zvS/bmtDv4x5wuXFzvWTByb0HGGpEP31RHoFRLdqJeP4htDU59Dzhen5ItYnmZzfcrW27z8PXZH4cHn8nUJJ0+ITqljn+mdRkXWBUfw5aFyTMI+Tj1dX1Cul1zjAgMBAAE=\n"
const enveloppeJeuReference = "vaultaire-pkg-sig-v1\nSHA256:CESJeFuVOKpsMuWTRGCplzfY9Rqi6PzrBGYdO+6UOBw\nB2byf+WK17F6PLFhneoHRD01n1ckdbc1Y/QHlOivCw59BAmpFT1yXEZPlTDiM/C6QRaEZsOPDSN2qHfzbPbEnaluqR0G8WRuN5QTKT1jIzMCK95He0TTBM98QNp8zHTFIT8Mo32Qo6i1qU7iY3rSZjnVnrFvcU4zRY/lVXwd4YxRCgJZ8iDpwZx+N9MIHHEUaX2OxPZE1VYMp141/ZPHazUfXEP5MR+DyXG6yOO5LtBo1umnZvBlTLDPAAtpWMMrt7XqU9eDHqafYLXzHgzOi2XVA3it9uYHvK584wLMrKw8eXloqzSBulD5mNTLieSS4lJitZHD7antQ3DWOaEdNiuQOB8IENpy48AO0CbKZo9W8NgZzAI56SX1BcLycvKwrfCjRuVchN6cxOyIBhjDdgODjQjalsiTRasSHwcnLobUmucDV/u08klmzhHm6ZMOPTRsjpt+Ej+/akI3OJiJ/PonI/c0paFr2aNU1lSDE0BYhXXS4iGv+HVZE6dDvXD2\n"
const signataireJeuReference = "-----BEGIN RSA PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsjXg3RSkLXiGKIe2o7JU\nLc3/LuoeM2FewuRmkr7qJ9zgfjGgg7amWxevZd4nLeNBOjOL91ec2yLmByB7aTMz\n3otCh8BhNLszPuig8WlbJPJQNkCnoFGzSPrsINMWp/03St34CyyDVUkc2tmyc4sB\n0haOfrHpUL/sfUS8uVsDLIIm63iQ7HZQrbLz9UBY4b2xPRrA5McvzPEsDgMK0vfQ\nwthzX6nC94ZxspgHeEP/LAYlJ8lCDeqUIi0X+uidsYPdnfr7jT6f4UJOxadoweOC\n6HyUbeuZqOesEGeYI5QJplQmlzpsNUuPYuQsF4CggwGOKsWUCxlIbetAxUfStyz/\nQzwkH3luuojqyWNkwesH3WgfYVpthkVW9UWPsZhB70cvGS4HMyjVJ4SgjZbJuXq1\n5wMLmAQ36WIitZdw2Lm0lWL+3sSM7hH+AxlM3Wh3ajtvgIHl5i2WzFyXizIwmaCs\nR4BI+LoiZotiW/8BKAMJetZRMyPmEghx+lrH/MFdk+3lAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
const fichierJeuReference = "# Clés publiques de signature des paquets d'agent du cluster Vaultaire.\n# Déposées à l'installation, puis tenues à jour par l'agent (jeux signés, TO-DO 207).\n# Un paquet dont le manifeste n'est pas signé par une clé de ce fichier est refusé.\n# vaultaire-pkg-trust n=2\n-----BEGIN RSA PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsjXg3RSkLXiGKIe2o7JU\nLc3/LuoeM2FewuRmkr7qJ9zgfjGgg7amWxevZd4nLeNBOjOL91ec2yLmByB7aTMz\n3otCh8BhNLszPuig8WlbJPJQNkCnoFGzSPrsINMWp/03St34CyyDVUkc2tmyc4sB\n0haOfrHpUL/sfUS8uVsDLIIm63iQ7HZQrbLz9UBY4b2xPRrA5McvzPEsDgMK0vfQ\nwthzX6nC94ZxspgHeEP/LAYlJ8lCDeqUIi0X+uidsYPdnfr7jT6f4UJOxadoweOC\n6HyUbeuZqOesEGeYI5QJplQmlzpsNUuPYuQsF4CggwGOKsWUCxlIbetAxUfStyz/\nQzwkH3luuojqyWNkwesH3WgfYVpthkVW9UWPsZhB70cvGS4HMyjVJ4SgjZbJuXq1\n5wMLmAQ36WIitZdw2Lm0lWL+3sSM7hH+AxlM3Wh3ajtvgIHl5i2WzFyXizIwmaCs\nR4BI+LoiZotiW/8BKAMJetZRMyPmEghx+lrH/MFdk+3lAgMBAAE=\n-----END RSA PUBLIC KEY-----\n-----BEGIN RSA PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAycGLmlXpy7sFnKXuJF00\nnlF9BuUuvR+5UTiLOTQasMTCk5w/x6bZ4jTHS8hXXJIZ3f2qRXoE88Y+MewaAI3p\n1hpqAAv0Oj2F8r6BXcKsxZZEWDytDPCW9eVXAf5Rx/PqdtTXFvk/nINJppgS1NRP\n69sXy5/RtNHuwVMt8Q+vy9ivCUC/9IowM8IhfuEicGoq9Rb5b5Edazylqx6szv0Y\nFCljTxWZ8KFYNOAnjsSgOWHpyV2YCvh74ingwZtvPKr9YJMQ995Yy0NRuFy/mvIJ\nxG4lVNa36aDFuP+ANlxuRB9GYb5rUDBJphQXf3X/f4rJ0wBguG9oYC9xKfQBh5k+\nPkdYrzC8otQFbfS/lwxbQoNZlYHrKHoxG6zFofupwQLOSRgH2zvS/bmtDv4x5wuX\nFzvWTByb0HGGpEP31RHoFRLdqJeP4htDU59Dzhen5ItYnmZzfcrW27z8PXZH4cHn\n8nUJJ0+ITqljn+mdRkXWBUfw5aFyTMI+Tj1dX1Cul1zjAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"

func TestLeVecteurDuJeuSeVerifie(t *testing.T) {
	signataire, err := LireClesPubliques([]byte(signataireJeuReference))
	if err != nil {
		t.Fatal(err)
	}
	env, err := LireEnveloppe(enveloppeJeuReference)
	if err != nil {
		t.Fatal(err)
	}
	j, err := VerifierJeu(corpsJeuReference, env, signataire)
	if err != nil {
		t.Fatalf("le jeu de référence ne se vérifie plus : %v", err)
	}
	if j.Numero != 2 || len(j.Cles) != 2 {
		t.Fatalf("%+v", j)
	}
	fichier, err := FichierCles(j)
	if err != nil || fichier != fichierJeuReference {
		t.Fatalf("le fichier d'une machine a changé :\n%s", fichier)
	}
	if NumeroDuFichier(fichier) != 2 {
		t.Error("numéro du fichier")
	}
	relu, err := LireClesPubliques([]byte(fichier))
	if err != nil || len(relu) != 2 {
		t.Fatalf("%v", err)
	}
	// Un octet du corps changé : refusé.
	if _, err := VerifierJeu(strings.Replace(corpsJeuReference, "\n2\n", "\n3\n", 1), env, signataire); err == nil {
		t.Error("un numéro retouché passe")
	}
}
