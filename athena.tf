# ==============================================================================
# Exploration & Threat Hunting SQL via Amazon Athena / Glue
# ==============================================================================
# Objectifs de sécurité :
# 1. Investigation post-incident (CSIRT / SOC) : Requêtage SQL serverless directement
#    sur les journaux JSON.gz stockés dans S3, sans infrastructure à maintenir.
# 2. Requêtes d'audit pré-enregistrées (Named Queries) couvrant les cas d'usage du TP.
# ==============================================================================

locals {
  athena_db_name = "${replace(var.project_name, "-", "_")}_cloudtrail_db"

  # Schéma officiel AWS CloudTrail pour le SerDe Hive JSON
  cloudtrail_columns = [
    { name = "eventversion", type = "string" },
    {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    },
    { name = "eventtime", type = "string" },
    { name = "eventsource", type = "string" },
    { name = "eventname", type = "string" },
    { name = "awsregion", type = "string" },
    { name = "sourceipaddress", type = "string" },
    { name = "useragent", type = "string" },
    { name = "errorcode", type = "string" },
    { name = "errormessage", type = "string" },
    { name = "requestparameters", type = "string" },
    { name = "responseelements", type = "string" },
    { name = "additionaleventdata", type = "string" },
    { name = "requestid", type = "string" },
    { name = "eventid", type = "string" },
    { name = "eventtype", type = "string" },
    { name = "recipientaccountid", type = "string" }
  ]
}

# Base de données Glue Catalog pour Athena
resource "aws_glue_catalog_database" "cloudtrail" {
  name        = local.athena_db_name
  description = "Base de donnees d'investigation des journaux AWS CloudTrail (${var.project_name})"
}

# Table externe pointant vers les logs CloudTrail du bucket S3
resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.cloudtrail.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL       = "TRUE"
    classification = "cloudtrail"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.cloudtrail_logs.id}/AWSLogs/${local.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "CloudTrailSerDe"
      serialization_library = "org.apache.hive.hcatalog.data.JsonSerDe"
      parameters = {
        "serialization.format" = "1"
      }
    }

    dynamic "columns" {
      for_each = local.cloudtrail_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# Workgroup Athena dédié avec emplacement des résultats dans S3 et destruction propre
resource "aws_athena_workgroup" "audit" {
  name          = "${var.project_name}-workgroup"
  description   = "Workgroup Athena pour l'analyse de securite CloudTrail"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false

    result_configuration {
      output_location = "s3://${aws_s3_bucket.cloudtrail_logs.id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

# 1. Requête d'exemple : Consultation des 100 derniers événements d'API
resource "aws_athena_named_query" "recent_events" {
  name        = "01-derniers-evenements-api"
  description = "Affiche les 100 derniers appels API enregistres par CloudTrail"
  workgroup   = aws_athena_workgroup.audit.id
  database    = aws_glue_catalog_database.cloudtrail.name
  query       = file("${path.module}/queries/01_recent_events.sql")
}

# 2. Requête d'exemple : Traçabilité du déploiement de l'instance EC2 (RunInstances)
resource "aws_athena_named_query" "ec2_creation" {
  name        = "02-creation-instance-ec2"
  description = "Retrouve qui a lance l'instance EC2 (RunInstances), quand et depuis quelle IP"
  workgroup   = aws_athena_workgroup.audit.id
  database    = aws_glue_catalog_database.cloudtrail.name
  query       = file("${path.module}/queries/02_ec2_run_instances.sql")
}

# 3. Requête d'exemple : Audit des sessions SSM Session Manager (StartSession)
resource "aws_athena_named_query" "ssm_sessions" {
  name        = "03-audit-sessions-ssm"
  description = "Liste toutes les ouvertures et fermetures de sessions shell via SSM Session Manager"
  workgroup   = aws_athena_workgroup.audit.id
  database    = aws_glue_catalog_database.cloudtrail.name
  query       = file("${path.module}/queries/03_ssm_sessions.sql")
}

# 4. Requête d'exemple : Détection des tentatives d'accès non autorisés (AccessDenied)
resource "aws_athena_named_query" "access_denied" {
  name        = "04-tentatives-acces-refuses"
  description = "Detecte les erreurs AccessDenied et UnauthorizedOperation (reconnaissance ou elevation de privileges)"
  workgroup   = aws_athena_workgroup.audit.id
  database    = aws_glue_catalog_database.cloudtrail.name
  query       = file("${path.module}/queries/04_access_denied.sql")
}
