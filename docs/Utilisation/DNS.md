# 📘 Documentation – DNS CLI (`vlt dns`)

Le module DNS est piloté via la commande principale :

vlt dns <commande> [arguments]


Il permet de gérer :
- les **zones DNS**
- les **enregistrements (A, CNAME, MX, NS, TXT)**
- le **reverse DNS (PTR)**

---

## 🆘 Aide

```sh
vlt dns -h
vlt dns help
vlt dns --help
```

---

## 🌍 Gestion des zones DNS

### ➕ Créer une zone DNS

```sh
vlt dns create_zone <nom_de_zone>
```

**Exemple**

```sh
vlt dns create_zone example.com
```

---

### 📋 Lister toutes les zones DNS

```sh
vlt dns get_zone
```

---

### 🔍 Afficher les enregistrements d’une zone

```sh
vlt dns get_zone <nom_de_zone>
```

**Exemple**

```sh
vlt dns get_zone example.com
```

---

## 🧾 Gestion des enregistrements DNS

### ➕ Ajouter un enregistrement

```sh
vlt dns add_record <fqdn> <type> <data> <ttl> [priority]
```

| Champ | Description |
|-----|------------|
| fqdn | Nom complet (ex: www.example.com) |
| type | A, CNAME, MX, NS, TXT |
| data | IP ou cible |
| ttl | Durée de vie (entier) |
| priority | Optionnel (défaut = 100, requis pour MX) |

---

### 🔹 A Record

```sh
vlt dns add_record www.example.com A 192.168.1.10 300
```

---

### 🔹 CNAME

```sh
vlt dns add_record blog.example.com CNAME www.example.com 300
```

---

### 🔹 MX

⚠️ Le nom doit commencer par `@.`

```sh
vlt dns add_record @.example.com MX mail.example.com 300 10
```

---

### 🔹 NS

```sh
vlt dns add_record @.example.com NS ns1.example.com 300
```

---

### 🔹 TXT

```sh
vlt dns add_record @example.com TXT "v=spf1 include:_spf.google.com ~all" 300
```

---

## ❌ Suppression DNS

### 🗑️ Supprimer une zone

```sh
vlt dns delete zone <nom.zone>
```

---

### 🗑️ Supprimer un enregistrement

```sh
vlt dns delete record <fqdn> <type>
```

**Exemple**

```sh
vlt dns delete record www.example.com A
```

---

### 🗑️ Supprimer un PTR

```sh
vlt dns delete ptr <ip>
```

---

## 🔁 Reverse DNS (PTR)

### 📄 Afficher tous les PTR

```sh
vlt dns get_ptr
```

---

## 🔐 Permissions

Toutes les commandes DNS sont soumises aux permissions utilisateur.  
En cas de refus :

Permission refusée : <raison>


---

## ⚠️ Règles & validations

- Les zones doivent exister avant ajout
- Les FQDN sont validés
- Les IP A doivent être valides
- MX / NS doivent commencer par `@.`
- La zone la plus spécifique est sélectionnée automatiquement

---

## 🧠 Exemple complet

```sh
vlt dns create_zone example.com
vlt dns add_record www.example.com A 192.168.1.10 300
vlt dns add_record @.example.com MX mail.example.com 300 10
vlt dns get_zone example.com
vlt dns get_ptr
```
