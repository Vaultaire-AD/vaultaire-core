gcc -fPIC -shared -o pam_login_custom_module.so pam_login_custom_module.c -lcurl -lpam
gcc -fPIC -shared -o pam_logout_custom_module.so pam_logout_custom_module.c -lcurl -lpam
gcc -fPIC -shared -o pam_ssh_auth_module.so pam_ssh_auth_module.c -lcurl -lpam
# cp ./pam_login_custom_module.so /usr/lib64/security/pam_login_custom_module.so
# cp ./pam_logout_custom_module.so /usr/lib64/security/pam_logout_custom_module.so

cp ./src/vaultaire_client/pam_module/pam_login_custom_module.so ./cmd/vaultaire_client/
cp ./src/vaultaire_client/pam_module/pam_logout_custom_module.so ./cmd/vaultaire_client/
cp ./src/vaultaire_client/pam_module/pam_ssh_auth_module.so ./cmd/vaultaire_client/