#!/bin/bash
# Script de Deploy Automatizado - SENTINELA Cloud
set -e

echo "[+] Iniciando Setup do SENTINELA na Nuvem..."

# 1. Atualização do Sistema
sudo apt-get update && sudo apt-get upgrade -y

# 2. Instalação de Dependências
sudo apt-get install -y docker.io docker-compose git python3-pip curl

# 3. Configuração do Docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ubuntu

# 4. Ajustes de Kernel para Kafka/OpenSearch (Necessário para a VM Ampere)
echo "[+] Aplicando ajustes de performance (sysctl)..."
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# 5. Firewall Interno (UFW)
echo "[+] Configurando Firewall (UFW)..."
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3000/tcp
sudo ufw --force enable

echo "[+] Setup de Base Concluído!"
echo "[!] Próximo passo: Clonar o repositório e rodar: docker-compose -f docker-compose.cloud.yml --profile full up -d"
