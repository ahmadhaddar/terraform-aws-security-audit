# ==============================================================================
# AWS CloudTrail Multi-Région (Pilier DICT : Traçabilité)
# ==============================================================================
# Objectifs de sécurité :
# 1. Couverture globale : Trail multi-région (`is_multi_region_trail = true`) et
#    inclusion des événements des services globaux IAM/STS (`include_global_service_events = true`).
# 2. Intégrité des journaux (Non-répudiation) : Validation cryptographique SHA-256
#    des fichiers de logs (`enable_log_file_validation = true`) pour détecter toute altération.
# ==============================================================================

resource "aws_cloudtrail" "main" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  # Enregistrement des événements de gestion (Management Events : Read & Write)
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = "${var.project_name}-logs-trail"
  }

  # CloudTrail vérifie la Bucket Policy lors de sa création : dépendance explicite obligatoire
  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs
  ]
}
