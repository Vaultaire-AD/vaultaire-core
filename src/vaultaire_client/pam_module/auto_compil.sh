# Build shared common object and PAM modules (run from pam_module directory)
set -e
# gcc -fPIC -c -o pam_common.o pam_common.c
gcc -fPIC -shared -o pam_login_custom_module.so pam_login_custom_module.c pam_common.c -lcurl -lpam
gcc -fPIC -shared -o pam_logout_custom_module.so pam_logout_custom_module.c pam_common.c -lcurl -lpam
gcc -fPIC -shared -o pam_ssh_auth_module.so pam_ssh_auth_module.c pam_common.c -lcurl -lpam

gcc -fPIC -shared -o libnss_vaultaire.so.2 nss_vaultaire.c

# Copy to cmd/vaultaire_client (when run from repo root)
# cp ./src/vaultaire_client/pam_module/pam_*.so cmd/vaultaire_client/
# When run from this directory:
# cp pam_login_custom_module.so pam_logout_custom_module.so pam_ssh_auth_module.so ../../../cmd/vaultaire_client/
