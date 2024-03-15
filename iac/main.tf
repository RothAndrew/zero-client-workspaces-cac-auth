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

data "aws_iam_policy_document" "workspaces" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["workspaces.amazonaws.com"]
    }
  }
}

#resource "aws_iam_role" "workspaces_default" {
#  name               = "workspaces_DefaultRole"
#  assume_role_policy = data.aws_iam_policy_document.workspaces.json
#}
#
#resource "aws_iam_role_policy_attachment" "workspaces_default_service_access" {
#  role       = aws_iam_role.workspaces_default.name
#  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonWorkSpacesServiceAccess"
#}
#
#resource "aws_iam_role_policy_attachment" "workspaces_default_self_service_access" {
#  role       = aws_iam_role.workspaces_default.name
#  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonWorkSpacesSelfServiceAccess"
#}

resource "aws_directory_service_directory" "managed_ad" {
  name     = var.active_directory_forest_domain_name
  password = var.dsrm_password
  edition = "Standard"
    type    = "MicrosoftAD"
  vpc_settings {
    subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[1]]
    vpc_id     = module.vpc.vpc_id
  }
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

resource "aws_security_group" "windows_bastion" {
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

#resource "aws_vpc_security_group_ingress_rule" "active_directory_server_allow_active_directory_ipv4" {
#  security_group_id = aws_security_group.active_directory_server.id
#  cidr_ipv4 = module.vpc.vpc_cidr_block
#  from_port = 389
#  to_port = 389
#  ip_protocol = "tcp"
#}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.windows_bastion.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv6" {
  security_group_id = aws_security_group.windows_bastion.id
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

resource "aws_iam_role_policy_attachment" "amazon_ssm_managed_instance_core" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "amazon_ssm_directory_service_access" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMDirectoryServiceAccess"
}

# Instance profile to attach the role to EC2 instance
resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "${local.name}-ssm-instance-profile"
  role = aws_iam_role.ssm_role.name
}

resource "aws_workspaces_ip_group" "managed_ad" {
  name = "Simple AD"
  description = "IP Allowlist for the Workspaces that use Simple AD"
  rules {
    source = "0.0.0.0/0"
    description = "Allow all"
  }
}

resource "aws_workspaces_directory" "managed_ad" {
  directory_id = aws_directory_service_directory.managed_ad.id
  subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[2]]
  ip_group_ids = [aws_workspaces_ip_group.managed_ad.id]
  self_service_permissions {
    change_compute_type = false
    increase_volume_size = true
    rebuild_workspace = true
    restart_workspace = true
    switch_running_mode = true
  }
  workspace_access_properties {
    device_type_android    = "ALLOW"
    device_type_chromeos   = "ALLOW"
    device_type_ios        = "ALLOW"
    device_type_linux      = "ALLOW"
    device_type_osx        = "ALLOW"
    device_type_web        = "ALLOW"
    device_type_windows    = "ALLOW"
    device_type_zeroclient = "ALLOW"
  }
  workspace_creation_properties {
    default_ou                          = var.workspace_default_ou
    enable_internet_access              = true
    enable_maintenance_mode             = true
    user_enabled_as_local_administrator = true
  }

#  depends_on = [
#    aws_iam_role_policy_attachment.workspaces_default_service_access,
#    aws_iam_role_policy_attachment.workspaces_default_self_service_access
#  ]
}

resource "aws_vpc_dhcp_options" "managed_ad_dhcp" {
  domain_name          = var.active_directory_forest_domain_name
  domain_name_servers  = aws_directory_service_directory.managed_ad.dns_ip_addresses
}

resource "aws_vpc_dhcp_options_association" "managed_ad_dns_resolver" {
  vpc_id          =  module.vpc.vpc_id
  dhcp_options_id = aws_vpc_dhcp_options.managed_ad_dhcp.id
}

data "aws_workspaces_bundle" "performance_windows_pcoip_base" {
  bundle_id = "wsb-39nl99v7l"
}

resource "aws_instance" "windows_bastion" {
  ami = data.aws_ami.windows.id
  instance_type = var.active_directory_server_instance_type
  availability_zone = data.aws_availability_zones.available.names[0]
  subnet_id = module.vpc.private_subnets[0]
  key_name = var.key_name
  get_password_data = true
  vpc_security_group_ids = [aws_security_group.windows_bastion.id]
  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name
  user_data = <<-EOF
<powershell>
# Install SSM Agent
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module AWS.Tools.Install -Force
Install-AWSToolsModule AWS.Tools.SSM -CleanUp -Force

# Turn on Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services,RSAT-ADDS -IncludeManagementTools -IncludeAllSubFeature

## Join the domain
#$domain = "${var.active_directory_forest_domain_name}"
#$username = "Admin"
#$password = "${var.dsrm_password}" | ConvertTo-SecureString -AsPlainText -Force
#$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username,$password
#Add-Computer -DomainName $domain -Credential $credential -Verbose -Restart
</powershell>
EOF
  tags = merge(
    local.tags,
    {
      Name = "${local.name}-active-directory-server"
    }
  )
  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --region=${var.region} --instance-ids ${aws_instance.windows_bastion.id}"
  }
  depends_on = [
    aws_vpc_dhcp_options_association.managed_ad_dns_resolver
  ]
}

resource "aws_ssm_document" "windows_bastion_join_domain" {
  name = "windows-bastion-join-domain"
  document_type = "Command"
  content = jsonencode(
    {
      schemaVersion = "2.2"
      description = "aws:domainJoin"
      mainSteps = [
        {
          action = "aws:domainJoin"
          name = "domainJoin"
          inputs = {
            directoryId = aws_directory_service_directory.managed_ad.id
            directoryName = aws_directory_service_directory.managed_ad.name
            dnsIpAddresses = aws_directory_service_directory.managed_ad.dns_ip_addresses
          }
        }
      ]
    }
  )
}

resource "aws_ssm_association" "windows_bastion_join_domain" {
  name = aws_ssm_document.windows_bastion_join_domain.name
  targets {
    key = "InstanceIds"
    values = [aws_instance.windows_bastion.id]
  }
  wait_for_success_timeout_seconds = 600
}

resource "null_resource" "port_forward_to_windows_bastion" {

}

#resource "aws_workspaces_workspace" "simple_ad" {
#  directory_id = aws_workspaces_directory.simple_ad.id
#  bundle_id = data.aws_workspaces_bundle.performance_windows_pcoip_base.id
#  user_name = "Administrator" #doesn't work
#  # TODO: change these to true
#  root_volume_encryption_enabled = false
#  user_volume_encryption_enabled = false
#  workspace_properties {
#    compute_type_name = "VALUE"
#    running_mode = "AUTO_STOP"
#    running_mode_auto_stop_timeout_in_minutes = 60
#  }
#}
