variable "aws_region" {
  description = "Région AWS cible pour le déploiement de l'infrastructure (Stockholm par défaut pour le TP)"
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Préfixe utilisé pour nommer toutes les ressources du projet"
  type        = string
  default     = "secu-cloud-g1"
}

variable "environment" {
  description = "Environnement de déploiement (lab, staging, prod)"
  type        = string
  default     = "lab"
}

variable "instance_type" {
  description = "Type d'instance EC2 pour la cible d'audit SSM"
  type        = string
  default     = "t3.micro"
}

variable "log_retention_days" {
  description = "Durée de rétention (en jours) des journaux de session SSM dans CloudWatch Logs"
  type        = number
  default     = 14
}

variable "configure_ssm_preferences" {
  description = "Active la configuration automatique du document régional SSM-SessionManagerRunShell vers CloudWatch"
  type        = bool
  default     = true
}
