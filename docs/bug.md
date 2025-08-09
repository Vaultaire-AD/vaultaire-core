# Historique des bug sur vaultaire 
✅ -> patch  
❌ -> pas encore patch

-----------------------------------------------------------------------------

- ✅ bug sur l'affichage lors de la creation d'un client  -> correction des string de sortie
- ✅ bug sur l'afficahge lors de la creation d'un groupe  et sur la creation du groupe en lui même -> patch retrait de la permission pour la creation d'un groupe
```bash
[2025-03-12 15:29] erreur lors de l'association du groupe à la permission CreateGroupe:
Error 1452 (23000): Cannot add or update a child row: a foreign key constraint fails
 (vaultaire.group_permission, CONSTRAINT group_permission_ibfk_2 FOREIGN KEY (d_id_permission)
REFERENCES permission (id_permission) ON DELETE CASCADE)
```

- ✅ bug sur vlt get -g groupename si le groupe name exsite pas l'app crash -> correction sur le return nil nil   
- ✅ bug sur le delete de client -> patch bug sur les switchs  
- ✅ bug remove perm client depuis cli -> patch erreur de table dans la requete
- ✅ bug sur la connection local sur les modules pam quand le serveur est injoignable -> patch
- ✅ -> bug sur la creation de users



