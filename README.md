Devops-technical-assignment
Technical assignment for interview

 Автор: Елизабет Иванова
 Дата:06.10.2025 

This repository contains the solution for a technical assignment focusing on Certificate Expiry Checking (Bash/Docker/K8s).

1. Task 1: Certificate Expiry Checker
This solution uses a Bash script to check the SSL/TLS expiry date for a list of domains, containerized with Docker, and orchestrated via Kubernetes.

1.1. Components File Description
check_cert.sh - Bash script using openssl to extract expiry dates and calculate remaining days. Implements WARNING (30 days) and CRITICAL (7 days) thresholds.
domains.conf - Configuration file containing the list of domains to check.
Dockerfile
cert-checker-k8s.yaml -Kubernetes Job manifest to run the script once inside a Minikube/K8s cluster.

1.2. Execution (Minikube/K8s)
Build Docker Image:
  - docker build -t ssl-checker:latest .
Load Image into K8s:
  - minikube image load ssl-checker:latest
Run the K8s Job:
  - kubectl apply -f cert-checker-k8s.yaml
View Results:
  - kubectl logs job/ssl-checker-job
