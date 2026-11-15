# ==============================================================================
# CloudWatch Logs & Journalisation Session Manager (SSM)
# ==============================================================================
# Objectifs de sécurité :
# 1. Complémentarité d'audit : CloudTrail trace l'appel API `StartSession` (qui et quand),
#    tandis que Session Manager + CloudWatch Logs tracent toutes les commandes shell exécutées.
# 2. Maîtrise du cycle de vie : Rétention définie explicitement (14 jours par défaut).
# ==============================================================================

resource "aws_cloudwatch_log_group" "ssm_sessions" {
  name              = "${var.project_name}-logs-ssm"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-logs-ssm"
  }
}

# Document régional de préférences Session Manager (journalisation automatique vers CloudWatch Logs)
resource "aws_ssm_document" "session_manager_prefs" {
  count = var.configure_ssm_preferences ? 1 : 0

  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Document regional de preferences Session Manager gere par Terraform"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName                = ""
      s3KeyPrefix                 = ""
      s3EncryptionEnabled         = true
      cloudWatchLogGroupName      = aws_cloudwatch_log_group.ssm_sessions.name
      cloudWatchEncryptionEnabled = false
      cloudWatchStreamingEnabled  = true
      idleSessionTimeout          = "20"
      maxSessionDuration          = ""
      kmsKeyId                    = ""
      runAsEnabled                = false
      runAsDefaultUser            = ""
      shellProfile = {
        windows = ""
        linux   = ""
      }
    }
  })

  tags = {
    Name = "${var.project_name}-ssm-preferences"
  }
}
