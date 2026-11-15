-- Détection SOC / Threat Hunting : Identification des appels d'API refusés (reconnaissance ou abus de privilèges)
SELECT
    useridentity.arn AS actor_arn,
    sourceipaddress,
    eventsource,
    eventname,
    errorcode,
    COUNT(*) AS denied_count
FROM cloudtrail_logs
WHERE errorcode IN ('AccessDenied', 'Client.UnauthorizedOperation')
   OR errorcode LIKE '%UnauthorizedOperation%'
GROUP BY
    useridentity.arn,
    sourceipaddress,
    eventsource,
    eventname,
    errorcode
ORDER BY denied_count DESC
LIMIT 50;
