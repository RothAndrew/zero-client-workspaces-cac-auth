terraform {
  required_version = ">= 1.0.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 6.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0, < 4.0.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.7.0, < 1.0.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "random_id" "default" {
  byte_length = 2
}

locals {
  name                          = "${var.name_prefix}-${lower(random_id.default.hex)}"
#  access_log_bucket_name_prefix = "${local.name}-accesslogs"
  tags = merge(
    var.tags,
    {
      DeployedBy = data.aws_caller_identity.current.arn,
    }
  )
}

module "vpc" {
  source                       = "git::https://github.com/defenseunicorns/terraform-aws-uds-vpc.git?ref=v0.1.5"
  name                         = local.name
  tags                         = local.tags
  vpc_cidr                     = var.vpc_cidr
  azs                          = [data.aws_availability_zones.available.names[0], data.aws_availability_zones.available.names[1], data.aws_availability_zones.available.names[2]]
  public_subnets               = [for k, v in module.vpc.azs : cidrsubnet(module.vpc.vpc_cidr_block, 5, k)]
  private_subnets              = [for k, v in module.vpc.azs : cidrsubnet(module.vpc.vpc_cidr_block, 5, k + 4)]
  create_database_subnet_group = false
  instance_tenancy             = "default"
  enable_nat_gateway           = true
  single_nat_gateway           = true
  create_default_vpc_endpoints = var.create_default_vpc_endpoints
}

data "aws_ami" "windows" {
  most_recent = true
  owners = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "active_directory_server" {
  name = "${local.name}-active-directory-server-sg"
  description = "Security Group for the Active Directory Server"
  vpc_id      = module.vpc.vpc_id
  tags = merge(
    local.tags,
    {
      Name = "${local.name}-active-directory-server-sg"
    }
  )
}

resource "aws_vpc_security_group_ingress_rule" "active_directory_server_allow_active_directory_ipv4" {
  security_group_id = aws_security_group.active_directory_server.id
  cidr_ipv4 = module.vpc.vpc_cidr_block
  from_port = 389
  to_port = 389
  ip_protocol = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.active_directory_server.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv6" {
  security_group_id = aws_security_group.active_directory_server.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

# IAM role for EC2 instances to allow access via Session Manager
resource "aws_iam_role" "ssm_role" {
  name = "${local.name}-ssm-role-for-ec2"

  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

# Instance profile to attach the role to EC2 instance
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${local.name}-ssm-instance-profile"
  role = aws_iam_role.ssm_role.name
}

resource "aws_instance" "active_directory_server" {
  ami = data.aws_ami.windows.id
  instance_type = var.active_directory_server_instance_type
  availability_zone = data.aws_availability_zones.available.names[0]
  subnet_id = module.vpc.private_subnets[0]
  key_name = var.key_name
  get_password_data = true
  vpc_security_group_ids = [aws_security_group.active_directory_server.id]
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  user_data = <<-EOF
<powershell>
# Install SSM Agent
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
#Install-Module AWS.Tools.Install -Force
#Install-AWSToolsModule AWS.Tools.SSM -CleanUp -Force

 # Turn on Active Directory Domain Services
Add-WindowsFeature AD-Domain-Services

# Create the forest
$Password = ConvertTo-SecureString "${var.dsrm_password}" -AsPlainText -Force
Install-ADDSForest -DomainName ${var.active_directory_forest_domain_name} -InstallDns -NoRebootOnCompletion -SafeModeAdministratorPassword $Password -Force

# Restart the computer
Restart-Computer -Force

</powershell>
EOF
  tags = merge(
    local.tags,
    {
      Name = "${local.name}-active-directory-server"
    }
  )
}