# Guide pour rédiger des tests unitaires en Go

## 1. Où placer les fichiers de test ?

- Les fichiers de test doivent être placés dans le même dossier que le code source qu’ils testent.
- Leur nom doit se terminer par `_test.go`.

Exemple :  
Si ton fichier de code est `serveur.go`, le fichier de test associé sera `serveur_test.go`.

---

## 2. Structure d’un fichier de test

Un fichier de test Go contient une ou plusieurs fonctions commençant par `Test` et prenant un paramètre `t` de type `*testing.T`.

```go
package nom_du_package

import "testing"

func TestNomDeLaFonction(t *testing.T) {
    // code de test ici
}
```

---

## 3. Exemple simple

Voici un exemple complet d’un fichier de test pour une fonction `Add` qui additionne deux entiers.

**Fichier :** `mathutils.go`

```go
package mathutils

func Add(a, b int) int {
    return a + b
}
```

**Fichier de test :** `mathutils_test.go`

```go
package mathutils

import "testing"

func TestAdd(t *testing.T) {
    got := Add(2, 3)
    want := 5

    if got != want {
        t.Errorf("Add(2, 3) = %d; want %d", got, want)
    }
}
```

---

## 4. Exécuter les tests

Pour lancer les tests, utilise la commande suivante dans le terminal à la racine du projet :

```bash
go test ./...
```

Cette commande lance tous les tests récursivement dans les sous-dossiers.

---

## 5. Conseils pratiques

- Nommer les fonctions de test clairement (`TestFonctionNominale`, `TestFonctionCasLimite`, etc.).
- Tester les cas positifs et négatifs.
- Utiliser `t.Errorf` ou `t.Fatalf` pour signaler une erreur.
- Ajouter des commentaires pour expliquer les tests complexes.

---

Tu peux maintenant créer tes fichiers `_test.go` en suivant ce modèle simple et efficace !
