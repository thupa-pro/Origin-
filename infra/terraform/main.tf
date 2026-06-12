# Origin Network — Infrastructure as Code (AWS)
# This is a stub. Full deployment configures:
# - ECS Fargate for services/*
# - DynamoDB for IVG policy cache
# - KMS for signing key management
# - CloudFront + S3 for .origin statement distribution
# - WAF for API Gateway protection

terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "production"
}
