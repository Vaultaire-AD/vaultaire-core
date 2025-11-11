#!/bin/sh
# Initialisation de l’administrateur Vaultaire

# Créer le groupe d’administration
/opt/vaultaire/vaultaire_cli create -g "Administration_Group" administration.vaultaire.local

# Créer l’utilisateur administrateur
/opt/vaultaire/vaultaire_cli create -u adm-lviguie vaultaire.local SuperAdminPass123 09/11/1998 "Lorens Viguie"

# Ajouter l’utilisateur au groupe d’administration
/opt/vaultaire/vaultaire_cli add -u adm-lviguie -g Administration_Group

# Créer la permission globale "*"
/opt/vaultaire/vaultaire_cli create -p -u "Vaultaire_Global_Admin" "*"

# Associer cette permission au groupe d’administration
/opt/vaultaire/vaultaire_cli add -gu Administration_Group -p Vaultaire_Global_Admin


/opt/vaultaire/vaultaire_cli update -p -u Vaultaire_Global_Admin auth all

/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin auth all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin compare all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin search all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin can_read all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin can_write all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin api_read_permission all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin api_write_permission all
/opt/vaultaire/vaultaire_cli update -pu Vaultaire_Global_Admin web_admin all
   
echo "✅ Utilisateur 'adm-lviguie' créé avec droits * complets dans administration.vaultaire.local"
