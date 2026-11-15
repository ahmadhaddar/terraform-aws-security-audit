# ==============================================================================
# Stockage S3 Durci pour les Journaux d'Audit CloudTrail
# ==============================================================================
# Objectifs de sécurité :
# 1. Confidentialité : Blocage total de l'accès public (Block Public Access) + Chiffrement SSE-S3
# 2. Intégrité : Versioning activé + Bucket Policy restreinte au seul service CloudTrail du compte
# 3. Sécurité en transit : Refus explicite de toute requête HTTP non chiffrée (aws:SecureTransport = false)
# 4. Cycle de vie Lab : force_destroy = true pour garantir un `terraform destroy` sans résidu
# ==============================================================================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  trail_name = "${var.project_name}-trail"
  trail_arn  = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket_prefix = "${var.project_name}-trail-logs-"
  force_destroy = true # Permet à `terraform destroy` de vider et supprimer le bucket automatiquement

  tags = {
    Name = "${var.project_name}-cloudtrail-bucket"
  }
}

# Blocage strict de tout accès public (prévention de la mauvaise configuration cloud)
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Activation du versioning pour protéger l'historique des fichiers de logs contre l'écrasement
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Chiffrement systématique au repos (SSE-S3 AES-256)
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Politique de bucket restrictive suivant le principe du moindre privilège
data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  # 1. Autoriser CloudTrail à vérifier les ACL du bucket
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # 2. Autoriser CloudTrail à écrire uniquement dans le préfixe AWSLogs/<account_id>/
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # 3. Forcer le chiffrement en transit (TLS/HTTPS obligatoire)
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.cloudtrail_logs.arn,
      "${aws_s3_bucket.cloudtrail_logs.arn}/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}
