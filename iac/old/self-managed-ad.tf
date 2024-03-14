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