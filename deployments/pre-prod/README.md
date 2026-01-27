podman build -f deployments/pre-prod/Dockerfile -t vaultaire-ad:latest .  
podman tag localhost/vaultaire-ad:latest 192.168.1.73:5000/vaultaire-ad:latest  
podman push --tls-verify=false 192.168.1.73:5000/vaultaire-ad:latest  
