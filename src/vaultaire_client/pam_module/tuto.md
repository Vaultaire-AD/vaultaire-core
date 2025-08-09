# Compiler le module PAM :

```bash
gcc -fPIC -shared -o pam_custom.so pam_module.c -lcurl -lpam

ou 
gcc -fPIC -fno-stack-protector -c pam_custom_module.c 
gcc -o pam_custom_module.so -shared -fPIC pam_custom_module.o -lcurl -lpam

cp ./pam_custom.so /usr/lib64/security/pam_custom.so
```

Configurer PAM : Modifie /etc/pam.d/sshd ou un autre service PAM, en ajoutant la ligne :

auth required pam_custom.so

Tester l’intégration :

    Démarre ton serveur Go.
    Tente une connexion SSH pour voir si l'authentification est redirigée vers ton client Go.