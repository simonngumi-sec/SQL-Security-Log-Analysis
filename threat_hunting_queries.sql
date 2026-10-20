-- ====================================================================
-- Project: Security Operations Center (SOC) Log Analysis
-- Author: Simon Ngumi Mwaura (simonngumi-sec)
-- Description: SQL queries designed to audit web server logs, 
--              detect potential SQL Injection (SQLi) patterns, 
--              and identify suspicious IP activity.
-- ====================================================================

-- --------------------------------------------------------------------
-- Query 1: Detect Suspicious Web Requests (SQL Injection Audit)
-- Scenario: The WAF flagged potential SQLi payloads on the web app.
-- Objective: Identify IP addresses sending requests containing single 
--            quotes or OR logic in the request URI, and count occurrences.
-- --------------------------------------------------------------------

SELECT 
    web_requests.ip_address,
    COUNT(web_requests.request_id) AS suspicious_request_count
FROM 
    web_requests
INNER JOIN 
    users ON web_requests.user_id = users.user_id
WHERE 
    web_requests.request_uri LIKE '%''%' 
    OR web_requests.request_uri LIKE '%OR%'
GROUP BY 
    web_requests.ip_address
ORDER BY 
    suspicious_request_count DESC;

-- --------------------------------------------------------------------
-- Query 2: Authentication Anomaly Detection (Brute Force Hunting)
-- Objective: Find usernames experiencing a high volume of failed logins.
-- --------------------------------------------------------------------

SELECT 
    users.username,
    COUNT(login_attempts.attempt_id) AS failed_attempts
FROM 
    users
INNER JOIN 
    login_attempts ON users.user_id = login_attempts.user_id
WHERE 
    login_attempts.status = 'FAILED'
GROUP BY 
    users.username
HAVING 
    COUNT(login_attempts.attempt_id) >= 5
ORDER BY 
    failed_attempts DESC;
