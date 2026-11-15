# ==============================================================================
# Rôle IAM & Profil d'Instance EC2 (Moindre Privilège)
# ==============================================================================
# Objectifs de sécurité :
# 1. Moindre privilège : Remplacement de l'ancienne politique dépréciée `AmazonEC2RoleforSSM`
#    par `AmazonSSMManagedInstanceCore` (recommandation officielle AWS).
# 2. Cloisonnement des logs : Politique inline restreignant l'écriture CloudWatch Logs
#    exclusivement au groupe de journaux des sessions SSM de ce projet.
# ==============================================================================

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    sid     = "AllowEC2AssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2_ssm" {
  name               = "${var.project_name}-ec2-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  description        = "Role IAM moindre privilege pour l'administration EC2 via SSM Session Manager"

  tags = {
    Name = "${var.project_name}-ec2-ssm-role"
  }
}

# Attachement de la politique minimale gérée par AWS pour l'agent SSM
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ec2_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Politique inline restrictive pour envoyer les journaux de session vers CloudWatch Logs
data "aws_iam_policy_document" "ssm_session_logs" {
  statement {
    sid    = "AllowDescribeLogGroups"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]
    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*"
    ]
  }

  statement {
    sid    = "AllowWriteToSSMSessionLogGroupOnly"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "${aws_cloudwatch_log_group.ssm_sessions.arn}:*"
    ]
  }
}

resource "aws_iam_role_policy" "ssm_session_logs" {
  name   = "${var.project_name}-ssm-cw-logs-policy"
  role   = aws_iam_role.ec2_ssm.id
  policy = data.aws_iam_policy_document.ssm_session_logs.json
}

# Profil d'instance attaché à l'EC2
resource "aws_iam_instance_profile" "ec2_ssm" {
  name = "${var.project_name}-ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm.name
}
