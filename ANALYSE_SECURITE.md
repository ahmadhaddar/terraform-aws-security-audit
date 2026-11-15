# Fiche d'Analyse de Sécurité — Groupe 1 (TP 1 : CloudTrail, Athena & Session Manager)

**Module :** Sécurité dans le Cloud Computing (M2 SRCC — ESGI)  
**Enseignante :** Mme Saba BEROL  
**Sujet :** TP 1 — CloudTrail & traçabilité des actions AWS  
**Pilier DICT dominant :** **Traçabilité (T)**  

---

## 1. Positionnement dans le Modèle DICT et dans le Modèle de Responsabilité Partagée AWS

### 1.1 Positionnement dans la grille DICT (et correspondance CIA + AAA)
Le modèle **DICT** évalue le besoin de protection d'un actif informationnel selon quatre critères : **D**isponibilité, **I**ntégrité, **C**onfidentialité, **T**raçabilité (équivalent à la triade anglo-saxonne **CIA** complétée par le triptyque **AAA** : *Authentication, Authorization, Accounting*).

| Pilier DICT | Rôle dans notre architecture TP 1 | Niveau d'implication |
| :--- | :--- | :--- |
| **Traçabilité (T)** *(Dominant)* | **Cœur du sujet (*Accounting* du modèle AAA) :** Capacité à savoir **qui** a fait **quoi**, **quand**, **depuis où** et **avec quel résultat**. Assurée par **AWS CloudTrail** (appels d'API du compte interrogés via **Athena**) et **SSM Session Manager + CloudWatch Logs** (commandes shell exécutées sur l'EC2). Garantit l'**imputabilité** et la **non-répudiation**. | **Principal (4/4)** |
| **Intégrité (I)** | **Protection des preuves d'audit :** Un journal d'audit n'a de valeur probante (post-mortem ou juridique) que s'il n'a pas été altéré. Assurée par `enable_log_file_validation = true` (empreintes SHA-256 chaînées et signées par CloudTrail), le versioning S3 et une Bucket Policy stricte. | **Secondaire fort (3/4)** |
| **Confidentialité (C)** | **Protection des métadonnées sensibles et des accès :** Les logs contiennent des ARN, adresses IP et paramètres d'infrastructure. Assurée par le blocage total de l'accès public S3 (`block_public_access`), le chiffrement au repos (SSE-S3 / EBS), le chiffrement en transit (TLS imposé par `DenyInsecureTransport`), l'approche **Zero-SSH** et le **moindre privilège IAM**. | **Secondaire fort (3/4)** |
| **Disponibilité (D)** | **Continuité de la collecte :** S3 et CloudWatch Logs offrent une haute durabilité native multi-AZ au sein de la région `eu-north-1`. *(La résilience inter-région fait l'objet du TP 5).* | **Standard (2/4)** |

### 1.2 Positionnement dans le Modèle de Responsabilité Partagée AWS
Comme vu au **Chapitre 1 (Fondamentaux)** du cours :
* **AWS est responsable de la sécurité *du* Cloud :** Sécurité physique des datacenters, disponibilité de l'API CloudTrail, fiabilité du moteur d'exécution Athena, isolation de l'hyperviseur Nitro EC2 et maintien de l'infrastructure SSM.
* **Le Client (notre groupe) est responsable de la sécurité *dans* le Cloud :**
  1. **Activation et périmètre de l'audit :** Configurer un Trail CloudTrail explicite, multi-région, avec persistance long terme dans S3 (sans quoi seul l'historique éphémère de 90 jours existe).
  2. **Sécurisation de la donnée d'audit :** Configurer le chiffrement, bloquer l'accès public au bucket S3 (éviter la **mauvaise configuration**, risque n°1 propre au cloud) et définir la rétention CloudWatch Logs.
  3. **Gestion des privilèges (IAM) et durcissement système/réseau :** Remplacer SSH (port 22) par SSM Session Manager, imposer IMDSv2 sur l'EC2 et appliquer le moindre privilège sur le rôle IAM (`AmazonSSMManagedInstanceCore`).

---

## 2. Réponses Détaillées aux 5 Questions de Compréhension du Sujet

### Question 1 : En quoi CloudTrail répond-il spécifiquement au pilier « Traçabilité » du modèle DICT, et pas aux trois autres piliers ?

**Réponse :**
1. **Pourquoi il répond spécifiquement à la Traçabilité (T) :**
   * Le cours définit la **Traçabilité** (le *Accounting* du modèle AAA) comme la capacité à enregistrer chronologiquement les actions réalisées sur le système afin d'**authentifier l'acteur**, d'**imputer la responsabilité d'une action** (imputabilité) et d'empêcher un utilisateur de nier l'avoir effectuée (non-répudiation).
   * Chaque événement JSON généré par CloudTrail contient les champs fondamentaux d'investigation vus en cours (Chapitre 3 – *Logging & Monitoring*) :
     * **`userIdentity` (Qui ?)** : Utilisateur IAM, rôle assumé (`AssumedRole`), compte Root ou service AWS.
     * **`eventTime` (Quand ?)** : Horodatage précis en UTC.
     * **`eventSource` & `eventName` (Quoi ?)** : Service ciblé (`ec2.amazonaws.com`, `iam.amazonaws.com`) et action appelée (`RunInstances`, `StartSession`, `StopLogging`).
     * **`sourceIPAddress` & `userAgent` (D'où et comment ?)** : Adresse IP source et outil utilisé (Console, AWS CLI, Terraform).
     * **`errorCode` & `errorMessage` (Résultat)** : Permet de tracer les échecs (`AccessDenied`, `UnauthorizedOperation`).

2. **Pourquoi il ne répond PAS aux trois autres piliers (D, I, C) :**
   * Dans la typologie des **7 types de contrôles** vue en cours, CloudTrail est un **contrôle purement détectif** (*« Voir ce qui se passe »*), et non un contrôle **préventif**, **correctif** ou de **recouvrement** :
     * **Pas de Confidentialité (C) :** CloudTrail n'empêche jamais un utilisateur malveillant ou trop privilégié de lire un secret ou d'exfiltrer un bucket S3 ; il se contente d'enregistrer que l'accès a eu lieu (ce sont IAM, KMS et les Security Groups qui assurent la Confidentialité en contrôle préventif).
     * **Pas d'Intégrité (I) du SI :** CloudTrail n'empêche pas la modification ou la suppression d'une ressource ou d'une donnée métier ; il journalise l'appel `DeleteBucket` ou `TerminateInstances` *après* ou *pendant* son exécution.
     * **Pas de Disponibilité (D) :** CloudTrail ne maintient aucun service en ligne, n'effectue aucun équilibrage de charge (ALB) ni aucune sauvegarde/réplication de données métier permettant de réduire le RTO en cas de panne.

---

### Question 2 : Le cours cite le « manque de visibilité » comme l'un des grands défis de la sécurité cloud. Montrez, avec votre architecture, comment CloudTrail réduit ce défi — et où il ne suffit pas.

**Réponse :**
1. **Pourquoi le manque de visibilité est un défi majeur du Cloud :**
   * Dans le cloud, le client fait abstraction du matériel physique détenu par le CSP (AWS) et pilote une infrastructure dynamique et éphémère entièrement par des appels d'API. Sans journalisation centralisée (vulnérabilité citée dans l'**OWASP Top 10** rappelée au Chapitre 3 du cours), les changements d'état passent inaperçus jusqu'à l'impact.

2. **Comment CloudTrail (couplé à Athena) réduit ce défi dans notre architecture :**
   * **Visibilité globale sur le Control Plane :** En activant `is_multi_region_trail = true` et `include_global_service_events = true`, notre trail capture 100 % des actions d'administration et de gestion sur toutes les régions AWS, même si un attaquant tente de créer des ressources cachées dans une région inhabituelle (ex. `ap-east-1`).
   * **Exploitabilité immédiate via Athena :** Les millions de lignes JSON stockées dans S3 sont structurées et interrogeables en SQL en quelques secondes (recherche de `RunInstances`, chasse aux `AccessDenied`, détection de création de clés IAM).

3. **Où CloudTrail ne suffit pas (Ses angles morts et comment notre architecture les comble) :**
   * **Angle mort n°1 — L'activité à l'intérieur du système d'exploitation (OS / Shell) :** CloudTrail enregistre l'appel API `ssm:StartSession` (il sait *qui* a ouvert une session shell sur l'instance EC2), mais **il est totalement aveugle sur les commandes tapées à l'intérieur du terminal Linux** (`cat /etc/passwd`, `curl`, élévation `sudo`).  
     $\rightarrow$ *Notre parade dans le TP 1 :* Nous complétons CloudTrail par la journalisation **SSM Session Manager vers CloudWatch Logs** (`secu-cloud-g1-logs-ssm`), qui enregistre chaque commande tapée et sa sortie.
   * **Angle mort n°2 — Les flux réseau (Couches 3 et 4 OSI) :** CloudTrail ne voit aucun paquet réseau (scan Nmap, ping ICMP, requêtes HTTP vers un serveur web Apache, tentative d'exfiltration TCP).  
     $\rightarrow$ *Complément vu en cours (TP 2) :* Il faut activer les **VPC Flow Logs** pour obtenir la visibilité réseau.
   * **Angle mort n°3 — L'absence de réaction temps réel si utilisé seul avec S3 :** CloudTrail livre ses logs dans S3 avec un délai de **5 à 15 minutes**. Utilisé seul avec S3/Athena, il permet l'**investigation a posteriori (CSIRT)** mais pas l'alerte immédiate. Pour du temps réel (**SOC**), il faut le coupler à des *CloudWatch Metric Filters + Alarmes SNS* ou *Amazon GuardDuty*.

---

### Question 3 : Pourquoi remplacer l'accès SSH classique par Session Manager change-t-il la surface d'attaque de l'instance ? Reliez votre réponse à la notion de « défense locale » vue en cours.

**Réponse :**
1. **Rappel des notions du cours (Chapitre 3 & 4 — Défense en profondeur & Sécurité de l'infrastructure) :**
   * La **surface d'attaque** correspond à l'ensemble des points d'entrée exposés qu'un attaquant peut cibler lors de sa phase de reconnaissance (ports ouverts, services en écoute, clés et identifiants).
   * La **défense locale** protège directement un composant individuel ou *endpoint* (dans le cloud : Security Group attaché à l'instance, pare-feu hôte, configuration de l'OS), par opposition à la **défense globale** qui protège l'architecture dans son ensemble (VPC, IAM centralisé, gestion des incidents).

2. **Comment le passage de SSH à SSM Session Manager réduit drastiquement la surface d'attaque :**
   * **Suppression des ports entrants ouverts (Défense locale — Security Group) :** Avec SSH classique, le Security Group doit ouvrir le port **TCP/22** en entrée (`ingress`), exposant le démon `sshd` aux scans de ports (Shodan, Nmap), aux attaques par force brute et aux éventuelles vulnérabilités zero-day d'OpenSSH (ex. *regreSSHion*). Avec Session Manager, **notre Security Group (`ec2_zero_ssh`) possède zéro règle entrante**. L'agent SSM sur l'instance initie uniquement une connexion **sortante HTTPS (port 443)** vers l'API AWS SSM.
   * **Pas besoin d'adresse IP publique ni de Bastion Host :** L'instance peut résider dans un sous-réseau privé sans être joignable depuis Internet.
   * **Élimination du risque lié aux clés SSH statiques (Authentification sans secret permanent) :** Comme le souligne le Chapitre 4 du cours, les mots de passe et clés statiques (`.pem` qui finissent oubliées sur un poste développeur ou commitées par erreur sur GitHub) sont une vulnérabilité majeure. Avec SSM, aucune paire de clés n'est créée (`key_name = null`).
   * **Centralisation IAM + MFA et Traçabilité native (Défense globale + locale) :** L'accès est contrôlé par les politiques **IAM** (jetons STS temporaires) et chaque session ainsi que chaque commande tapée sont tracées dans CloudTrail et CloudWatch Logs, alors qu'un utilisateur root connecté en SSH peut facilement effacer son fichier `~/.bash_history`.

---

### Question 4 : Dans le modèle de responsabilité partagée AWS, qui est responsable de l'activation et de la configuration de CloudTrail : AWS ou le client ? Justifiez avec le cours (chapitre Fondamentaux – Responsabilité).

**Réponse :**
* **C'est le CLIENT qui est entièrement responsable de l'activation, de la configuration et de l'exploitation de CloudTrail.**
* **Justification avec le cours (Chapitre 1 — Fondamentaux : Responsabilité partagée) :**
  1. Le principe fondamental énonce : **« Le fournisseur (AWS) est responsable de la sécurité *du* cloud ; le client est responsable de la sécurité de *ce qu'il met dans* le cloud »**.
  2. Bien qu'AWS mette à disposition l'outil natif CloudTrail et garantisse la disponibilité et la sécurité de l'infrastructure qui fait tourner ce service (sécurité *du* cloud), AWS conserve uniquement par défaut un historique d'événements de gestion de 90 jours non immuable.
  3. Il appartient **exclusivement au client** d'activer un **Trail persistant**, de choisir sa couverture (**multi-région** ou non, événements de données S3/Lambda), d'activer la **validation d'intégrité des fichiers de logs**, de **sécuriser le bucket S3 récepteur** (chiffrement, blocage public, Bucket Policy) et surtout de **surveiller/exploiter ces journaux** (via Athena, CloudWatch ou un SIEM).
  4. Le cours rappelle d'ailleurs que **l'absence de logging et de monitoring** ainsi que la **mauvaise configuration** des outils fournis par le CSP relèvent de la responsabilité directe du client.

---

### Question 5 : Si le bucket S3 recevant les logs CloudTrail était mal configuré (accès public), quel principe du cours serait violé, et quelle conséquence concrète cela aurait-il pour une investigation post-incident ?

**Réponse :**
1. **Principes du cours violés :**
   * **En accès public en lecture (`s3:GetObject` ouvert à `*`) :** Violation directe du pilier **Confidentialité (C)** du modèle DICT et du **principe du moindre privilège**. C'est l'exemple type du défi **« Mauvaise configuration »** cité au Chapitre 1 du cours et de la vulnérabilité **« Logs exposés / mal protégés »** du Chapitre 4.
   * **En accès public en écriture/suppression (`s3:PutObject` / `s3:DeleteObject` ouvert à `*`) :** Violation directe des piliers **Intégrité (I)** et **Traçabilité (T)** du modèle DICT (vulnérabilité n°5 du Chapitre 4 : *« Logs absents ou effaçables — l'attaquant efface ses traces »*).

2. **Conséquences concrètes pour une investigation post-incident (CSIRT / Forensics) :**
   * **Cartographie gratuite pour l'attaquant (Fuite d'informations critiques) :** Les logs CloudTrail contiennent tous les identifiants de compte, les ARN des rôles IAM, la structure des ressources déployées, les adresses IP des administrateurs et les erreurs de configuration. Un attaquant qui lit ce bucket public réalise toute sa **phase de reconnaissance** sans même toucher aux serveurs de l'entreprise.
   * **Perte totale de valeur probante et d'imputabilité (Anti-Forensics) :** Si le bucket est mal protégé en écriture/suppression, l'attaquant peut **supprimer les fichiers `.json.gz`** correspondant à la fenêtre temporelle de son intrusion ou **injecter de faux journaux** pour accuser un tiers ou masquer sa persistance (création de backdoor IAM).
   * **Conséquence juridique et réglementaire (RGPD / ISO 27001) :** Lors des phases d'*Identification*, d'*Éradication* et d'*Enseignements (post-mortem)* de la réponse à incident (Chapitre 2 du cours), le CSIRT est incapable de déterminer l'étendue réelle de la compromission (impossible de prouver quelles données ont été touchées auprès de la CNIL), et les journaux altérés deviennent **irrecevables juridiquement** (perte de la non-répudiation).
   * *Notre parade dans le code Terraform (`s3.tf`) :* Ressource `aws_s3_bucket_public_access_block` avec les 4 verrous à `true`, `enable_log_file_validation = true` sur CloudTrail (toute modification d'un log casse la chaîne de hachage SHA-256) et `aws_s3_bucket_versioning` activé.

---

## 3. Fiche Mémo — Questions Transverses du Jury (Pour les 4 membres du groupe)

Le sujet précise que le jury peut poser à **n'importe quel membre du groupe** des questions transverses portant sur l'ensemble du cours et des autres TPs. Voici les points clés à connaître par cœur :

| Thème / Autre Groupe | Question transverse type du jury | Réponse synthétique attendue |
| :--- | :--- | :--- |
| **Pyramide de la sécurité (Chap. 1)** | *Quelle est la différence entre Sécurité de l'information, SSI, Cybersécurité et Sécurité informatique ?* | 1. **Sécurité de l'info** = le **but** (protéger l'info sous toutes ses formes : papier, oral, numérique).<br>2. **SSI** = stratégie **interne/organisationnelle** (PSSI, gouvernance, ISO 27001, RGPD).<br>3. **Cybersécurité** = stratégie **externe/opérationnelle** face aux cybermenaces.<br>4. **Sécurité informatique** = **l'exécution technique** (pare-feu, IAM, chiffrement, Terraform). |
| **Les 7 types de contrôle (Chap. 1)** | *Citez les types de contrôles du cours avec un exemple AWS.* | • **Directif :** Politiques IAM / Organisations.<br>• **Préventif :** Chiffrement KMS, Security Group, WAF.<br>• **Dissuasif :** Bannière d'avertissement légal.<br>• **Détectif :** **CloudTrail (TP1)**, **VPC Flow Logs + Alarmes (TP2)**, GuardDuty.<br>• **Compensatoire :** Bloquer un flux sur le pare-feu en attendant un patch (ex. Log4J).<br>• **Correctif :** **SSM Patch Manager (TP3)**.<br>• **Recouvrement :** **Réplication S3 cross-région (TP5)**, sauvegardes. |
| **CloudTrail (TP1) vs VPC Flow Logs (TP2)** | *Quelle différence entre la traçabilité du Groupe 1 et celle du Groupe 2 ?* | • **CloudTrail (TP1)** trace les **appels d'API du plan de contrôle AWS** (qui crée/modifie une ressource AWS).<br>• **VPC Flow Logs (TP2)** trace les **métadonnées des flux réseau IP** (IP source/dest, ports, protocole, `ACCEPT`/`REJECT`) au niveau des interfaces réseau du VPC, sans capturer le contenu des paquets. |
| **Patch Management (TP3) & DICT** | *Pourquoi le Patch Management SSM (Groupe 3) est-il rattaché à la Disponibilité et quel est le risque ?* | Un système non patché subit des attaques (ransomware, DoS) qui détruisent la **Disponibilité**. Mais à l'inverse, appliquer des patchs trop agressivement sans les tester peut casser la production (arbitrage sécurité vs disponibilité) : d'où l'usage d'une *Patch Baseline* (délai d'approbation) et d'une *Maintenance Window*. |
| **Réplication S3 & RTO (TP5)** | *Répliquer les logs d'un Load Balancer dans une 2e région (Groupe 5) suffit-il à garantir un bon RTO de l'application ?* | **Non.** Répliquer uniquement les logs S3 protège la **disponibilité et la traçabilité des journaux**, mais si la région primaire tombe, le serveur web EC2 et l'ALB tombent aussi. Pour un vrai Plan de Reprise d'Activité (DR) avec RTO faible, il faut aussi déployer l'application (EC2 + ALB) dans la 2e région avec un basculement DNS (Route 53). |
| **Chiffrement SSE-S3 vs SSE-KMS (TP6)** | *Quelle différence entre SSE-S3 (notre TP1) et SSE-KMS avec clé client CMK (Groupe 6) ?* | • **SSE-S3 :** AWS gère la clé de bout en bout ; tout utilisateur ayant le droit `s3:GetObject` déchiffre automatiquement l'objet.<br>• **SSE-KMS (CMK) :** Le client contrôle la **Key Policy** (double contrôle IAM + KMS : même un admin S3 ne peut pas lire l'objet s'il n'a pas le droit `kms:Decrypt`) et chaque usage de la clé est tracé dans CloudTrail. |
| **Réponse à Incident : SOC vs CSIRT (Chap. 2)** | *Quelle différence entre SOC et CSIRT, et quelles sont les 6 phases d'un incident ?* | • **SOC :** Surveillance et **détection** en continu (N1, N2, N3) via SIEM.<br>• **CSIRT :** Équipe d'**intervention** après détection.<br>• **6 phases :** 1. Préparation $\rightarrow$ 2. Identification $\rightarrow$ 3. Confinement $\rightarrow$ 4. Éradication $\rightarrow$ 5. Retour à la normale $\rightarrow$ 6. Enseignements (Post-mortem / RETEX). |
