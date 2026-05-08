# Terraform Infrastructure para SENTINELA (AWS)

Este diretório contém os skeletons profissionais para subir o SENTINELA na AWS usando Terraform.

## Componentes:
- **VPC & Subnets**: Rede isolada para os serviços.
- **Security Groups**: Regras de firewall para Kafka, Postgres e APIs.
- **EKS/ECS Skeleton**: Estrutura para orquestração de containers.
- **RDS (Postgres)**: Banco de dados gerenciado.

## Como usar:
1. Instale o Terraform CLI.
2. Configure suas credenciais AWS.
3. Execute `terraform init`.
4. Execute `terraform plan` para visualizar as mudanças.
5. **Aviso**: Não execute `terraform apply` sem revisar os custos e limites da sua conta.
