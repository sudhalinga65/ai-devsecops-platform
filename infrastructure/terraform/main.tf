/**
 * AI-Powered DevSecOps Platform - Infrastructure as Code
 * Terraform configuration for deploying the platform on AWS
 */

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "ai-devsecops-terraform-state"
    key            = "platform/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AI-DevSecOps-Platform"
      Environment = var.environment
      ManagedBy   = "Terraform"
      CostCenter  = "Engineering"
    }
  }
}

# VPC and Networking
module "vpc" {
  source = "./modules/vpc"

  environment       = var.environment
  vpc_cidr          = var.vpc_cidr
  availability_zones = var.availability_zones

  enable_nat_gateway   = true
  single_nat_gateway   = var.environment != "production"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Component = "Networking"
  }
}

# EKS Cluster for AI Agents
module "eks" {
  source = "./modules/eks"

  cluster_name    = "ai-devsecops-${var.environment}"
  cluster_version = "1.28"

  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids

  node_groups = {
    ai_agents = {
      desired_capacity = var.environment == "production" ? 3 : 2
      max_capacity     = var.environment == "production" ? 10 : 4
      min_capacity     = var.environment == "production" ? 2 : 1

      instance_types = ["t3.xlarge", "t3a.xlarge"]
      capacity_type  = "SPOT"  # 70% cost savings
      disk_size      = 50

      labels = {
        role = "ai-agents"
      }

      taints = []
    }

    system = {
      desired_capacity = 2
      max_capacity     = 3
      min_capacity     = 1

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      disk_size      = 30

      labels = {
        role = "system"
      }
    }
  }

  tags = {
    Component = "Kubernetes"
  }
}

# RDS PostgreSQL for AI Agent State and Metrics
module "rds" {
  source = "./modules/rds"

  identifier     = "ai-devsecops-db-${var.environment}"
  engine_version = "15.4"

  instance_class = var.environment == "production" ? "db.r6g.xlarge" : "db.t4g.medium"
  allocated_storage = var.environment == "production" ? 100 : 20
  max_allocated_storage = var.environment == "production" ? 500 : 100

  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  allowed_cidr_blocks = [module.vpc.vpc_cidr]

  database_name   = "ai_devsecops"
  master_username = "admin"

  multi_az               = var.environment == "production"
  backup_retention_period = var.environment == "production" ? 30 : 7
  deletion_protection    = var.environment == "production"

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = true

  tags = {
    Component = "Database"
  }
}

# ElastiCache Redis for Agent Communication
module "elasticache" {
  source = "./modules/elasticache"

  cluster_id           = "ai-devsecops-cache-${var.environment}"
  engine_version       = "7.0"
  node_type            = var.environment == "production" ? "cache.r6g.large" : "cache.t4g.medium"
  num_cache_nodes      = var.environment == "production" ? 3 : 1
  parameter_group_name = "default.redis7"

  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  allowed_cidr_blocks = [module.vpc.vpc_cidr]

  automatic_failover_enabled = var.environment == "production"
  multi_az_enabled           = var.environment == "production"

  tags = {
    Component = "Cache"
  }
}

# S3 Bucket for ML Models and Logs
resource "aws_s3_bucket" "ml_models" {
  bucket = "ai-devsecops-ml-models-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Component = "Storage"
    Purpose   = "ML-Models"
  }
}

resource "aws_s3_bucket_versioning" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "ml_models" {
  bucket = aws_s3_bucket.ml_models.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SageMaker Endpoint for Cost Prophet ML Model
resource "aws_sagemaker_model" "cost_prophet" {
  name               = "cost-prophet-${var.environment}"
  execution_role_arn = aws_iam_role.sagemaker_execution.arn

  primary_container {
    image          = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/cost-prophet:latest"
    model_data_url = "s3://${aws_s3_bucket.ml_models.bucket}/models/cost-prophet/model.tar.gz"
  }

  tags = {
    Component = "ML-Model"
    Agent     = "CostProphet"
  }
}

resource "aws_sagemaker_endpoint_configuration" "cost_prophet" {
  name = "cost-prophet-endpoint-config-${var.environment}"

  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.cost_prophet.name
    initial_instance_count = var.environment == "production" ? 2 : 1
    instance_type          = var.environment == "production" ? "ml.m5.xlarge" : "ml.t3.medium"

    serverless_config {
      max_concurrency   = 10
      memory_size_in_mb = 2048
    }
  }

  tags = {
    Component = "ML-Endpoint"
  }
}

resource "aws_sagemaker_endpoint" "cost_prophet" {
  name                 = "cost-prophet-endpoint-${var.environment}"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.cost_prophet.name

  tags = {
    Component = "ML-Endpoint"
    Agent     = "CostProphet"
  }
}

# IAM Role for SageMaker
resource "aws_iam_role" "sagemaker_execution" {
  name = "ai-devsecops-sagemaker-execution-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Component = "IAM"
  }
}

resource "aws_iam_role_policy_attachment" "sagemaker_execution" {
  role       = aws_iam_role.sagemaker_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

# Lambda Functions for Event Processing
resource "aws_lambda_function" "event_processor" {
  filename      = "${path.module}/lambda/event_processor.zip"
  function_name = "ai-devsecops-event-processor-${var.environment}"
  role          = aws_iam_role.lambda_execution.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300
  memory_size   = 1024

  environment {
    variables = {
      ENVIRONMENT    = var.environment
      EKS_CLUSTER    = module.eks.cluster_name
      RDS_ENDPOINT   = module.rds.endpoint
      REDIS_ENDPOINT = module.elasticache.endpoint
    }
  }

  vpc_config {
    subnet_ids         = module.vpc.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  tags = {
    Component = "Serverless"
  }
}

# Security Group for Lambda
resource "aws_security_group" "lambda" {
  name        = "ai-devsecops-lambda-${var.environment}"
  description = "Security group for Lambda functions"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "lambda-sg"
    Component = "Security"
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_execution" {
  name = "ai-devsecops-lambda-execution-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Component = "IAM"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "ai_agents" {
  name              = "/aws/ai-devsecops/agents/${var.environment}"
  retention_in_days = var.environment == "production" ? 90 : 7

  kms_key_id = aws_kms_key.cloudwatch.arn

  tags = {
    Component = "Logging"
  }
}

# KMS Key for CloudWatch Logs Encryption
resource "aws_kms_key" "cloudwatch" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Component = "Encryption"
  }
}

resource "aws_kms_alias" "cloudwatch" {
  name          = "alias/ai-devsecops-cloudwatch-${var.environment}"
  target_key_id = aws_kms_key.cloudwatch.key_id
}

# SNS Topic for Alerts
resource "aws_sns_topic" "alerts" {
  name              = "ai-devsecops-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.cloudwatch.id

  tags = {
    Component = "Notifications"
  }
}

# Data sources
data "aws_caller_identity" "current" {}
