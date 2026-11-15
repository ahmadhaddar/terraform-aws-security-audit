output "aws_account_id" {
  description = "Identifiant du compte AWS audité"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "Région AWS de déploiement"
  value       = data.aws_region.current.name
}

output "cloudtrail_bucket_name" {
  description = "Nom du bucket S3 sécurisé stockant les journaux CloudTrail et résultats Athena"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_name" {
  description = "Nom du trail CloudTrail multi-région"
  value       = aws_cloudtrail.main.name
}

output "ec2_instance_id" {
  description = "ID de l'instance EC2 cible (sans SSH, accessible via SSM)"
  value       = aws_instance.audit_target.id
}

output "ssm_connect_command" {
  description = "Commande AWS CLI prête à l'emploi pour ouvrir une session shell SSM sur l'instance"
  value       = "aws ssm start-session --region ${var.aws_region} --target ${aws_instance.audit_target.id}"
}

output "ssm_cloudwatch_log_group" {
  description = "Nom du groupe de logs CloudWatch recevant les commandes tapées dans Session Manager"
  value       = aws_cloudwatch_log_group.ssm_sessions.name
}

output "athena_workgroup_name" {
  description = "Workgroup Athena à sélectionner dans la console pour exécuter les requêtes enregistrées"
  value       = aws_athena_workgroup.audit.name
}

output "athena_database_name" {
  description = "Base de données Glue/Athena contenant la table cloudtrail_logs"
  value       = aws_glue_catalog_database.cloudtrail.name
}
