dans ce pacakge golang il y a toutes la partie basic du ducky network 
la partie authentification 

sevrver via 01 et client via 02

ce packge vise a etre le package commun a tous les client service
il manque donc toutes la logique d'enrollement et la partie gestion du cluster ducky 

ainsi que la possibilité d'ajouter des gestionaire de trames externe comme 07 pour le serveur web dans le futur

l'idée c'est que on importe le dossier comme un package avec la possibilité avant de lacner le serveur ajouter des gestionnaire de trames externe au package 

des trames qui seront propre a certain service

---

## État

FAIT — point d'entrée `ducky` : `ducky.Start(opts)` enchaîne enrôlement (si
besoin), connexion, askkey, 01 puis 02, et ne rend la main qu'une fois le client
authentifié.

FAIT — Spliter extensible : `ducky.Handle("06", monHandler)` avant `Start`.
02 est fourni, 01 est traité hors Spliter (ses réponses sont lues de façon
synchrone, avant que la boucle de réception ne démarre).

FAIT — enrôlement 01_05 à 01_09, des deux côtés. La clé publique du service ne
pouvait pas passer par une enveloppe RSA (1116 octets pour 446 utiles) : une clé
de session temporaire, elle, y tient, et ouvre le canal symétrique qui porte la
clé publique.

FAIT — configuration en YAML, même format que vaultaire_client.

RESTE — la gestion du cluster (04) : enregistrement, battement de cœur, sortie.

Mode d'emploi et prérequis : voir [UTILISATION.md](UTILISATION.md).
Format des trames : `docs/Developement/Tableau_Protocole_Réseau.md`.
