-- Traçabilité des accès distants Zero-SSH : Sessions ouvertes et fermées via SSM Session Manager
SELECT
    eventtime,
    useridentity.arn AS actor_arn,
    eventname,
    sourceipaddress,
    requestparameters,
    responseelements
FROM cloudtrail_logs
WHERE eventsource = 'ssm.amazonaws.com'
  AND eventname IN ('StartSession', 'TerminateSession', 'ResumeSession')
ORDER BY eventtime DESC
LIMIT 50;
