rm -rf /opt/pam_*
rm -rf /usr/lib64/security/pam_login_custom_module.c
rm -rf /usr/lib64/security/pam_logout_custom_module.c
nano pam_login_custom_module.c
nano pam_logout_custom_module.c

gcc -fPIC -shared -o pam_login_custom_module.so pam_login_custom_module.c -lcurl -lpam
gcc -fPIC -shared -o pam_logout_custom_module.so pam_logout_custom_module.c -lcurl -lpam
cp ./pam_login_custom_module.so /usr/lib64/security/pam_login_custom_module.so
cp ./pam_logout_custom_module.so /usr/lib64/security/pam_logout_custom_module.so