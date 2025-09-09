# Terraform Cheat Sheet

## Table of Contents
- [Installation and Setup](#installation-and-setup)
- [HCL Syntax](#hcl-syntax)
- [Providers](#providers)
- [Resources](#resources)
- [Variables and Outputs](#variables-and-outputs)
- [State Management](#state-management)
- [Modules](#modules)
- [Best Practices and Security](#best-practices-and-security)
- [Common Use Cases and Patterns](#common-use-cases-and-patterns)
- [Troubleshooting Tips](#troubleshooting-tips)

## Installation and Setup

### Installation Methods
```bash
# Install via package manager (Ubuntu/Debian)
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

# Install via Homebrew (macOS)
brew tap hashicorp/tap
brew install hashicorp/tap/terraform

# Install manually (Linux/macOS)
curl -LO https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip
unzip terraform_1.5.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# Install via Docker
docker run --rm -it hashicorp/terraform:latest version

# Verify installation
terraform version
```

### Basic Commands
```bash
# Initialize working directory
terraform init

# Validate configuration
terraform validate

# Plan changes
terraform plan
terraform plan -out=tfplan

# Apply changes
terraform apply
terraform apply tfplan
terraform apply -auto-approve

# Destroy infrastructure
terraform destroy
terraform destroy -auto-approve

# Format code
terraform fmt
terraform fmt -recursive

# Show current state
terraform show

# List resources in state
terraform state list

# Import existing resource
terraform import aws_instance.example i-1234567890abcdef0
```

## HCL Syntax

### Basic Structure
```hcl
# Comments
# Single line comment
/* Multi-line
   comment */

# Variable assignment
variable_name = "value"
number_var = 42
boolean_var = true
list_var = ["item1", "item2", "item3"]

# Object
object_var = {
  name = "example"
  size = "large"
  tags = {
    Environment = "production"
    Team        = "devops"
  }
}
```

### Data Types
```hcl
# Primitive Types
string_example = "hello world"
number_example = 42
bool_example = true

# Collection Types
list_example = ["a", "b", "c"]
set_example = toset(["a", "b", "c"])
map_example = {
  key1 = "value1"
  key2 = "value2"
}

# Complex Types
object_example = {
  name = "example"
  age  = 30
}

tuple_example = ["hello", 42, true]
```

### Functions and Expressions
```hcl
# String functions
upper("hello")          # "HELLO"
lower("HELLO")          # "hello"
length("hello")         # 5
substr("hello", 1, 3)   # "ell"
replace("hello", "l", "x") # "hexxo"

# Collection functions
length(["a", "b", "c"])    # 3
concat(["a"], ["b", "c"])  # ["a", "b", "c"]
contains(["a", "b"], "a")  # true
keys({a = 1, b = 2})       # ["a", "b"]
values({a = 1, "b" = 2})   # [1, 2]

# Conditional expressions
var.environment == "prod" ? "production" : "development"

# For expressions
[for s in var.list : upper(s)]
{for k, v in var.map : k => upper(v)}

# Splat expressions
var.users[*].name
var.users[*].attributes["department"]
```

## Providers

### Provider Configuration
```hcl
# AWS Provider
provider "aws" {
  region = "us-west-2"
  
  default_tags {
    tags = {
      Environment = "production"
      Project     = "my-project"
    }
  }
}

# Multiple AWS regions
provider "aws" {
  alias  = "us_east"
  region = "us-east-1"
}

# Azure Provider
provider "azurerm" {
  features {}
  
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}

# Google Cloud Provider
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  zone    = var.gcp_zone
}

# Version constraints
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}
```

### Backend Configuration
```hcl
# S3 Backend
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-west-2"
    
    # Optional: DynamoDB table for state locking
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}

# Azure Backend
terraform {
  backend "azurerm" {
    resource_group_name  = "tf-state-rg"
    storage_account_name = "tfstatestorage"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
  }
}

# GCS Backend
terraform {
  backend "gcs" {
    bucket = "my-tf-state-bucket"
    prefix = "terraform/state"
  }
}
```

## Resources

### AWS Resources
```hcl
# EC2 Instance
resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  
  vpc_security_group_ids = [aws_security_group.web.id]
  subnet_id              = aws_subnet.public.id
  
  user_data = file("${path.module}/user-data.sh")
  
  tags = {
    Name = "web-server"
  }
}

# Security Group
resource "aws_security_group" "web" {
  name_prefix = "web-"
  vpc_id      = aws_vpc.main.id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "main-vpc"
  }
}

# S3 Bucket
resource "aws_s3_bucket" "example" {
  bucket = "my-unique-bucket-name"
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Lambda Function
resource "aws_lambda_function" "example" {
  filename         = "lambda_function.zip"
  function_name    = "lambda_function_name"
  role            = aws_iam_role.lambda_role.arn
  handler         = "index.handler"
  source_code_hash = filebase64sha256("lambda_function.zip")
  runtime         = "python3.9"
  
  environment {
    variables = {
      FOO = "bar"
    }
  }
}
```

### Azure Resources
```hcl
# Resource Group
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "East US"
}

# Virtual Machine
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_B1s"
  admin_username      = "adminuser"
  
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
  
  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

# Storage Account
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
```

### Google Cloud Resources
```hcl
# Compute Instance
resource "google_compute_instance" "default" {
  name         = "test"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  
  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2004-lts"
    }
  }
  
  network_interface {
    network = "default"
    
    access_config {
      // Ephemeral public IP
    }
  }
  
  metadata_startup_script = file("startup.sh")
}

# Cloud Storage Bucket
resource "google_storage_bucket" "example" {
  name          = "example-bucket"
  location      = "US"
  force_destroy = true
}

# Cloud Function
resource "google_cloudfunctions_function" "function" {
  name        = "function-test"
  description = "My function"
  runtime     = "python39"
  
  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.example.name
  source_archive_object = google_storage_bucket_object.zip.name
  trigger {
    http_trigger {}
  }
  
  entry_point = "hello_http"
}
```

## Variables and Outputs

### Variable Definitions
```hcl
# variables.tf
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "development"
}

variable "instance_count" {
  description = "Number of instances"
  type        = number
  default     = 1
  
  validation {
    condition     = var.instance_count > 0 && var.instance_count <= 10
    error_message = "Instance count must be between 1 and 10."
  }
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b"]
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Owner       = "DevOps"
    Environment = "prod"
  }
}

variable "database_config" {
  description = "Database configuration"
  type = object({
    name     = string
    size     = string
    version  = string
    backup   = bool
  })
  default = {
    name     = "mydb"
    size     = "db.t3.micro"
    version  = "13.7"
    backup   = true
  }
}

# Sensitive variable
variable "database_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}
```

### Variable Assignment Methods
```bash
# Command line
terraform apply -var="environment=production" -var="instance_count=3"

# Environment variables
export TF_VAR_environment=production
export TF_VAR_instance_count=3
terraform apply

# terraform.tfvars file
environment = "production"
instance_count = 3
availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

# Variable files
terraform apply -var-file="production.tfvars"
```

### Outputs
```hcl
# outputs.tf
output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.web.id
}

output "instance_public_ip" {
  description = "Public IP address of the instance"
  value       = aws_instance.web.public_ip
}

output "database_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.database.endpoint
  sensitive   = true
}

# Complex output
output "instance_info" {
  description = "Instance information"
  value = {
    id        = aws_instance.web.id
    public_ip = aws_instance.web.public_ip
    az        = aws_instance.web.availability_zone
  }
}
```

## State Management

### State Commands
```bash
# Show state
terraform state show
terraform state show aws_instance.example

# List resources
terraform state list

# Move resource in state
terraform state mv aws_instance.example aws_instance.web

# Remove resource from state (without destroying)
terraform state rm aws_instance.example

# Pull remote state
terraform state pull

# Push state to remote
terraform state push terraform.tfstate

# Replace provider
terraform state replace-provider hashicorp/aws registry.terraform.io/hashicorp/aws

# Refresh state
terraform refresh
```

### State File Structure
```json
{
  "version": 4,
  "terraform_version": "1.5.0",
  "serial": 1,
  "lineage": "uuid",
  "outputs": {},
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "example",
      "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
      "instances": [
        {
          "schema_version": 1,
          "attributes": {
            "id": "i-1234567890abcdef0",
            "ami": "ami-0c02fb55956c7d316",
            "instance_type": "t2.micro"
          }
        }
      ]
    }
  ]
}
```

### Remote State
```hcl
# Data source for remote state
data "terraform_remote_state" "vpc" {
  backend = "s3"
  config = {
    bucket = "my-terraform-state"
    key    = "vpc/terraform.tfstate"
    region = "us-west-2"
  }
}

# Using remote state data
resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
  subnet_id     = data.terraform_remote_state.vpc.outputs.public_subnet_id
}
```

## Modules

### Creating a Module
```hcl
# modules/vpc/main.tf
variable "cidr_block" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

resource "aws_vpc" "main" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "main-vpc"
  }
}

resource "aws_subnet" "public" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.main.id
  
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "main-igw"
  }
}

# modules/vpc/outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}
```

### Using a Module
```hcl
# main.tf
module "vpc" {
  source = "./modules/vpc"
  
  cidr_block         = "10.0.0.0/16"
  availability_zones = ["us-west-2a", "us-west-2b"]
}

# Using module from registry
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = "single-instance"

  ami                    = "ami-ebd02392"
  instance_type          = "t2.micro"
  key_name               = "user1"
  monitoring             = true
  vpc_security_group_ids = ["sg-12345678"]
  subnet_id              = "subnet-eddcdzz4"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

# Reference module outputs
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = module.vpc.vpc_id
  
  # ... security group rules
}
```

### Module Sources
```hcl
# Local path
module "vpc" {
  source = "./modules/vpc"
}

# Git repository
module "vpc" {
  source = "git::https://example.com/vpc.git"
}

module "storage" {
  source = "git::ssh://username@example.com/storage.git"
}

# Terraform Registry
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"
}

# GitHub
module "consul" {
  source = "github.com/hashicorp/example"
}

# Generic Git repository
module "vpc" {
  source = "git::https://example.com/vpc.git?ref=v1.2.0"
}

# HTTP URLs
module "vpc" {
  source = "https://example.com/vpc-module.zip"
}

# S3 buckets
module "vpc" {
  source = "s3::https://s3-eu-west-1.amazonaws.com/example/vpc.zip"
}
```

## Best Practices and Security

### Code Organization
```hcl
# File structure
.
├── main.tf                 # Main configuration
├── variables.tf            # Variable definitions
├── outputs.tf              # Output definitions
├── versions.tf             # Provider versions
├── terraform.tfvars        # Variable values
├── modules/
│   └── vpc/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── environments/
    ├── dev/
    │   ├── main.tf
    │   └── terraform.tfvars
    └── prod/
        ├── main.tf
        └── terraform.tfvars
```

### Security Best Practices
```hcl
# Use sensitive variables
variable "database_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

# Avoid hardcoded secrets
resource "aws_db_instance" "example" {
  password = var.database_password  # Good
  # password = "hardcoded-secret"   # Bad
}

# Use data sources for existing resources
data "aws_vpc" "default" {
  default = true
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.bucket

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.example.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# Use resource naming conventions
resource "aws_instance" "web_server" {
  # Use descriptive names
  tags = {
    Name = "${var.environment}-web-server"
  }
}

# Implement resource locks
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Terraform Configuration
```hcl
# terraform.tf - Version constraints
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "state/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

# Enable experimental features
terraform {
  experiments = [module_variable_optional_attrs]
}
```

### Workspaces
```bash
# List workspaces
terraform workspace list

# Create workspace
terraform workspace new production

# Select workspace
terraform workspace select production

# Show current workspace
terraform workspace show

# Delete workspace
terraform workspace delete staging
```

## Common Use Cases and Patterns

### Multi-Environment Setup
```hcl
# environments/dev/main.tf
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "dev/terraform.tfstate"
    region = "us-west-2"
  }
}

module "infrastructure" {
  source = "../../modules/infrastructure"
  
  environment    = "dev"
  instance_type  = "t2.micro"
  min_size      = 1
  max_size      = 2
  
  tags = {
    Environment = "development"
    Team        = "devops"
  }
}

# environments/prod/main.tf
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-west-2"
  }
}

module "infrastructure" {
  source = "../../modules/infrastructure"
  
  environment    = "prod"
  instance_type  = "t3.medium"
  min_size      = 2
  max_size      = 10
  
  tags = {
    Environment = "production"
    Team        = "devops"
  }
}
```

### Data Sources
```hcl
# Get existing VPC
data "aws_vpc" "selected" {
  id = var.vpc_id
}

# Get latest AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Use data in resources
resource "aws_instance" "web" {
  ami               = data.aws_ami.amazon_linux.id
  instance_type     = "t2.micro"
  availability_zone = data.aws_availability_zones.available.names[0]
}
```

### Dynamic Blocks
```hcl
resource "aws_security_group" "example" {
  name = "example"

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      description = ingress.value.description
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }
}

# Variable definition
variable "ingress_rules" {
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  
  default = [
    {
      description = "HTTP"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTPS"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}
```

### Conditional Resources
```hcl
resource "aws_instance" "example" {
  count = var.create_instance ? 1 : 0
  
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"
}

# Using for_each with conditions
resource "aws_s3_bucket" "example" {
  for_each = var.create_buckets ? toset(var.bucket_names) : []
  
  bucket = each.key
}
```

## Troubleshooting Tips

### Common Issues and Solutions
```bash
# Verbose logging
export TF_LOG=DEBUG
export TF_LOG_PATH=terraform.log
terraform apply

# Validate configuration
terraform validate

# Format and validate
terraform fmt -check
terraform fmt -diff

# Check for potential issues
terraform plan -detailed-exitcode

# Force unlock state
terraform force-unlock LOCK_ID

# Recover from corrupted state
terraform state pull > backup.tfstate
terraform state push backup.tfstate

# Target specific resources
terraform plan -target=aws_instance.web
terraform apply -target=aws_instance.web

# Refresh state
terraform refresh

# Import existing resource
terraform import aws_instance.web i-1234567890abcdef0

# Show dependency graph
terraform graph | dot -Tsvg > graph.svg
```

### Debugging Techniques
```hcl
# Use locals for debugging
locals {
  debug_info = {
    environment = var.environment
    region      = var.aws_region
    vpc_id      = data.aws_vpc.selected.id
  }
}

output "debug" {
  value = local.debug_info
}

# Use console command
terraform console
> var.environment
> local.debug_info
> aws_instance.web.id
```

### Performance Optimization
```bash
# Parallelism control
terraform apply -parallelism=10

# Plugin cache
export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"
mkdir -p $TF_PLUGIN_CACHE_DIR

# Upgrade providers
terraform init -upgrade

# Compress state
terraform state pull | gzip > terraform.tfstate.gz
```

### Error Handling
```hcl
# Lifecycle management
resource "aws_instance" "example" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"

  lifecycle {
    create_before_destroy = true
    prevent_destroy       = true
    ignore_changes       = [ami, user_data]
  }
}

# Error handling in provisioners
resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t2.micro"

  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y nginx",
    ]
    
    on_failure = continue
  }
}
```

## Official Documentation Links

- [Terraform Documentation](https://www.terraform.io/docs)
- [Terraform Registry](https://registry.terraform.io/)
- [HCL Configuration Language](https://www.terraform.io/docs/language/index.html)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Terraform Azure Provider](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [Terraform Google Provider](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Terraform Enterprise](https://www.terraform.io/docs/enterprise/index.html)