-- Tâche 5 du TP1 : Retrouver l'événement de création de l'instance EC2 (RunInstances)
-- Répond aux questions d'imputabilité (Pilier T du DICT : Qui ? Quand ? D'où ? Quoi ?)
SELECT
    eventtime,
    useridentity.arn AS actor_arn,
    sourceipaddress,
    awsregion,
    requestparameters,
    responseelements
FROM cloudtrail_logs
WHERE eventname = 'RunInstances'
ORDER BY eventtime DESC
LIMIT 20;
