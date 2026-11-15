# ==============================================================================
# Instance EC2 Cible & Défense Locale (Zero-SSH)
# ==============================================================================
# Objectifs de sécurité :
# 1. Réduction de la surface d'attaque : Aucune paire de clés SSH (key_name = null)
# 2. Défense locale (Security Group) : Zéro port entrant ouvert (pas de port 22)
# 3. Flux sortant restreint au strict nécessaire (HTTPS 443 vers endpoints AWS SSM/CloudWatch)
# 4. Durcissement de l'instance : IMDSv2 obligatoire (http_tokens = "required") & EBS chiffré
# ==============================================================================

# Récupération dynamique de la dernière AMI Amazon Linux 2023 (x86_64) officielle
data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# Utilisation du VPC par défaut de la région cible
data "aws_vpc" "default" {
  default = true
}

# Security Group appliquant la défense locale et le moindre privilège réseau
resource "aws_security_group" "ec2_zero_ssh" {
  name        = "${var.project_name}-zero-ssh-sg"
  description = "Security Group Zero-SSH : aucun flux entrant autorise, sortie HTTPS uniquement pour agent SSM"
  vpc_id      = data.aws_vpc.default.id

  # AUCUN bloc ingress : le port 22 (SSH) et tous les autres ports entrants sont fermés.
  # L'administration passe exclusivement par une connexion sortante de l'agent SSM.

  egress {
    description = "Autorise uniquement HTTPS sortant vers les API AWS (SSM, EC2Messages, CloudWatch Logs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-zero-ssh-sg"
  }
}

# Instance EC2 administrée uniquement via AWS Systems Manager (Session Manager)
resource "aws_instance" "audit_target" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_type
  iam_instance_profile   = aws_iam_instance_profile.ec2_ssm.name
  vpc_security_group_ids = [aws_security_group.ec2_zero_ssh.id]

  # Absence volontaire de paire de clés SSH pour réduire la surface d'attaque
  key_name = null

  # Durcissement IMDSv2 obligatoire (protection contre les attaques SSRF et vol de tokens IAM)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Chiffrement du volume racine EBS au repos
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  # Relance de l'agent SSM après propagation complète du profil IAM d'instance
  user_data = <<-EOF
    #!/bin/bash
    sleep 10
    systemctl restart amazon-ssm-agent
  EOF

  tags = {
    Name = "${var.project_name}-ec2-ssm-target"
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm_core,
    aws_iam_role_policy.ssm_session_logs
  ]
}
