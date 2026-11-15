terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Course      = "M2-Securite-Cloud-Groupe1"
    }
  }
}

# Récupération dynamique des informations du compte et de la région (zéro secret ou ID en dur)
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
