resource "aws_directory_service_directory" "simple_ad" {
  name     = var.active_directory_forest_domain_name
  password = var.dsrm_password
  size = "Small"
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

#resource "aws_vpc_security_group_ingress_rule" "active_directory_server_allow_active_directory_ipv4" {
#  security_group_id = aws_security_group.active_directory_server.id
#  cidr_ipv4 = module.vpc.vpc_cidr_block
#  from_port = 389
#  to_port = 389
#  ip_protocol = "tcp"
#}

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

# # Turn on Active Directory Domain Services
#Add-WindowsFeature AD-Domain-Services
#
## Create the forest
#$Password = ConvertTo-SecureString "${var.dsrm_password}" -AsPlainText -Force
#Install-ADDSForest -DomainName ${var.active_directory_forest_domain_name} -InstallDns -NoRebootOnCompletion -SafeModeAdministratorPassword $Password -Force
#
## Restart the computer
#Restart-Computer -Force

</powershell>
EOF
  tags = merge(
    local.tags,
    {
      Name = "${local.name}-active-directory-server"
    }
  )
}

resource "aws_workspaces_ip_group" "simple_ad" {
  name = "Simple AD"
  description = "IP Allowlist for the Workspaces that use Simple AD"
  rules {
    source = "0.0.0.0/0"
    description = "Allow all"
  }
}

resource "aws_workspaces_directory" "simple_ad" {
  directory_id = aws_directory_service_directory.simple_ad.id
  subnet_ids = [module.vpc.private_subnets[0], module.vpc.private_subnets[2]]
  ip_group_ids = [aws_workspaces_ip_group.simple_ad.id]
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

resource "aws_vpc_dhcp_options" "simplead_dhcp" {
  domain_name          = var.active_directory_forest_domain_name
  domain_name_servers  = aws_directory_service_directory.simple_ad.dns_ip_addresses
}

resource "aws_vpc_dhcp_options_association" "simplead_dns_resolver" {
  vpc_id          =  module.vpc.vpc_id
  dhcp_options_id = aws_vpc_dhcp_options.simplead_dhcp.id
}

data "aws_workspaces_bundle" "performance_windows_pcoip_base" {
  bundle_id = "wsb-39nl99v7l"
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