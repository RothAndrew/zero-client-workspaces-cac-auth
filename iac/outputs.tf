output "region" {
  value = var.region
}

output "vpc_cidr" {
  value = var.vpc_cidr
}

output "windows_ami_id" {
  value = data.aws_ami.windows.id
}

output "active_directory_server_password" {
  value = rsadecrypt(aws_instance.active_directory_server.password_data, file("~/.ssh/id_rsa"))
  sensitive = true
}

output "active_directory_server_instance_id" {
  value = aws_instance.active_directory_server.id
}
