variable "region" {
  default = "us-east-1"
}

resource "aws_vpc" "sentinela_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  
  tags = {
    Name = "sentinela-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id     = aws_vpc.sentinela_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  
  tags = {
    Name = "sentinela-public-subnet"
  }
}

output "vpc_id" {
  value = aws_vpc.sentinela_vpc.id
}
