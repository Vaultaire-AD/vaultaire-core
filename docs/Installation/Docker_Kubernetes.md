# Installation via Docker / Kubernetes

## Docker
```bash
docker build -t mon-projet .
docker run -d -p 8080:8080 mon-projet
```

## Docker Compose
```bash
docker-compose up -d
```

## Kubernetes
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```
