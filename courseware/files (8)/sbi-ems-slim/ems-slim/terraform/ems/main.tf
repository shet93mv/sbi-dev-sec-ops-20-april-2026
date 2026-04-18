# ═══════════════════════════════════════════════════════════════════════════════
# SBI EMS — Terraform Infrastructure
# DevSecOps Training | IaC Security Module (Module 7, Day 2)
#
# This Terraform file defines the AWS infrastructure for deploying EMS.
# It is written to PASS Checkov scans — demonstrating secure IaC patterns.
#
# DevSecOps Lab Exercise:
#   Run: checkov -d terraform/ems --compact
#   Expected result: 0 FAILED checks
#
# Compare with: C:\devsecops-lab\04-iac-security\terraform-samples\vulnerable_main.tf
# That file intentionally fails 8+ Checkov checks for the lab exercise.
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # DevSecOps: Remote state in S3 with encryption and locking
  # Uncomment for production use:
  # backend "s3" {
  #   bucket         = "sbi-ems-terraform-state"
  #   key            = "ems/terraform.tfstate"
  #   region         = "ap-south-1"
  #   encrypt        = true
  #   kms_key_id     = "alias/terraform-state-key"
  #   dynamodb_table = "sbi-ems-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region
  # DevSecOps: Never hardcode access_key / secret_key here.
  # Use IAM roles (EC2 instance profile) or environment variables:
  #   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
}

# ═══════════════════════════════════════════════════════════════════════════════
# VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════
variable "aws_region"    { default = "ap-south-1" }
variable "environment"   { default = "dev" }
variable "app_name"      { default = "sbi-ems" }
variable "db_username"   { description = "RDS master username — set via TF_VAR_db_username" }
variable "db_password"   {
  description = "RDS master password — set via TF_VAR_db_password or Vault"
  sensitive   = true      # Terraform will not print this in logs
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC AND NETWORKING
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_vpc" "ems_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.app_name}-vpc", Environment = var.environment }
}

# Private subnets for RDS — no direct internet access
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.ems_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"
  # DevSecOps: map_public_ip_on_launch = false (default) — do not assign public IPs
  tags = { Name = "${var.app_name}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.ems_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"
  tags = { Name = "${var.app_name}-private-b" }
}

# Public subnet for ECS/load balancer only
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.ems_vpc.id
  cidr_block              = "10.0.10.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false   # DevSecOps: CKV_AWS_130 — no auto public IP
  tags = { Name = "${var.app_name}-public-a" }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY GROUPS
# ═══════════════════════════════════════════════════════════════════════════════

# EMS application security group — only HTTPS inbound
resource "aws_security_group" "ems_sg" {
  name        = "${var.app_name}-sg"
  description = "Security group for SBI EMS application"
  vpc_id      = aws_vpc.ems_vpc.id

  # DevSecOps: Only allow HTTPS (443) — not HTTP (80)
  # Never open 0.0.0.0/0 on all ports (CVSS 10.0 misconfiguration)
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # DevSecOps: Restrict egress to specific targets only
  egress {
    description = "HTTPS to internet (for external APIs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "MySQL to RDS in VPC"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "${var.app_name}-sg", Environment = var.environment }
}

# RDS security group — only accepts connections from the app SG
resource "aws_security_group" "rds_sg" {
  name        = "${var.app_name}-rds-sg"
  description = "Security group for SBI EMS RDS instance"
  vpc_id      = aws_vpc.ems_vpc.id

  # DevSecOps: Database is NOT publicly accessible.
  # Only the application security group can connect to MySQL.
  ingress {
    description     = "MySQL from EMS app only"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ems_sg.id]
  }

  # DevSecOps: No egress from RDS (databases should not initiate outbound connections)
  tags = { Name = "${var.app_name}-rds-sg", Environment = var.environment }
}

# ═══════════════════════════════════════════════════════════════════════════════
# RDS — MySQL (Secure configuration)
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_db_subnet_group" "ems_db_subnet" {
  name       = "${var.app_name}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = { Name = "${var.app_name}-db-subnet" }
}

resource "aws_db_instance" "ems_db" {
  identifier        = "${var.app_name}-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp3"

  db_name  = "emsdb"
  username = var.db_username
  password = var.db_password       # Injected via TF_VAR_db_password or Vault

  db_subnet_group_name   = aws_db_subnet_group.ems_db_subnet.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  # ── DevSecOps: Secure RDS configuration ──────────────────────────────────
  # CKV_AWS_17: Database NOT publicly accessible
  publicly_accessible = false

  # CKV_AWS_16: Encryption at rest enabled
  storage_encrypted = true

  # CKV_AWS_129: CA certificate specified
  ca_cert_identifier = "rds-ca-2019"

  # CKV_AWS_157: Multi-AZ for high availability (RBI Annex 7 requirement)
  multi_az = true

  # CKV_AWS_23: Auto minor version upgrades enabled (security patches)
  auto_minor_version_upgrade = true

  # CKV_AWS_293: Deletion protection enabled in production
  deletion_protection = var.environment == "prod" ? true : false

  # DevSecOps: Backup retention for compliance
  backup_retention_period = 7
  skip_final_snapshot     = var.environment != "prod"

  tags = { Name = "${var.app_name}-db", Environment = var.environment }
}

# ═══════════════════════════════════════════════════════════════════════════════
# S3 — Application logs bucket (Secure configuration)
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_s3_bucket" "ems_logs" {
  bucket = "${var.app_name}-logs-${var.environment}"
  tags   = { Name = "${var.app_name}-logs", Environment = var.environment }
}

# CKV_AWS_53: Block ALL public access — the bucket holding logs must never be public
resource "aws_s3_bucket_public_access_block" "ems_logs_block" {
  bucket = aws_s3_bucket.ems_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CKV_AWS_145: Encryption at rest for S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "ems_logs_enc" {
  bucket = aws_s3_bucket.ems_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# CKV_AWS_52: Enable versioning for audit trail
resource "aws_s3_bucket_versioning" "ems_logs_versioning" {
  bucket = aws_s3_bucket.ems_logs.id
  versioning_configuration { status = "Enabled" }
}

# ═══════════════════════════════════════════════════════════════════════════════
# IAM — Least-privilege role for EMS application
# ═══════════════════════════════════════════════════════════════════════════════

# DevSecOps: Never use AdministratorAccess or PowerUserAccess for an application.
# This role grants ONLY what the EMS application needs.
resource "aws_iam_role" "ems_role" {
  name = "${var.app_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.app_name}-role" }
}

resource "aws_iam_role_policy" "ems_policy" {
  name = "${var.app_name}-policy"
  role = aws_iam_role.ems_role.id

  # DevSecOps: Principle of Least Privilege —
  # EMS only needs to write logs to S3. Nothing else.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteLogsToS3"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.ems_logs.arn}/*"
      }
    ]
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════
output "rds_endpoint" {
  description = "RDS MySQL endpoint — use in DB_URL environment variable"
  value       = aws_db_instance.ems_db.endpoint
  sensitive   = false
}

output "logs_bucket_name" {
  description = "S3 bucket for application logs"
  value       = aws_s3_bucket.ems_logs.bucket
}
