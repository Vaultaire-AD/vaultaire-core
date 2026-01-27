sudo podman stop vaultaire
sudo podman rm vaultaire
sudo podman rmi localhost/pre-prod_vaultaire-ad
sudo podman-compose up -d
sudo podman logs vaultaire