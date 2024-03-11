variable "region" {
  description = "The AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "The prefix to use when naming all resources"
  type        = string
  default     = "zcwca"
  validation {
    condition     = length(var.name_prefix) <= 20
    error_message = "The name prefix cannot be more than 20 characters"
  }
}

variable "tags" {
  description = "A map of tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.200.0.0/16"
}

variable "active_directory_server_instance_type" {
  description = "The instance type to use for the Active Directory server"
    type        = string
  default = "m6i.large"
}

variable "key_name" {
  description = "The name of the key pair to use for access to the instance(s)"
  type = string
}

variable "create_default_vpc_endpoints" {
  description = "Whether to create default VPC endpoints"
  type        = bool
  default = false
}

variable "active_directory_forest_domain_name" {
  description = "The domain name for the Active Directory forest"
  type        = string
}

variable "dsrm_password" {
  description = "The password to use for Directory Services Restore Mode. Must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character."
  type = string
  sensitive = true
}
