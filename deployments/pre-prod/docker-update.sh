podman-compose -f deployments/pre-prod/docker-compose.yml
podman rmi localhost/vaultaire-preprod
git pull origin feature/pre-prod --no-rebase
./deployments/pre-prod/docker-build-and-up.sh 
