-- Tâche 5 du TP1 : Consultation générale des 100 derniers événements d'API tracés par CloudTrail
SELECT
    eventtime,
    useridentity.arn AS actor_arn,
    eventsource,
    eventname,
    sourceipaddress,
    awsregion,
    errorcode
FROM cloudtrail_logs
ORDER BY eventtime DESC
LIMIT 100;
