# ARGUS Security Report

## Executive Summary

ARGUS identified **2 critical**, **2 high**, **4 medium**, and **0 low** risk findings.

## Findings

### CRITICAL: Successful login from 192.168.1.100 after 5 failures

**Category:** auth  
**MITRE ATT&CK:** T1110, T1078  
**ID:** ARGUS-AUTH-003-192.168.1.100

User 'root' successfully logged in from 192.168.1.100 after 5 failed attempts. This may indicate a successful brute-force attack.

**Evidence:**

- `Failed attempts: 5`
- `Successful user: root`
- `Source IP: 192.168.1.100`

**Recommendation:** Investigate session for root from 192.168.1.100. Check for unauthorized access.

---

### CRITICAL: Successful login from 172.16.0.5 after 3 failures

**Category:** auth  
**MITRE ATT&CK:** T1110, T1078  
**ID:** ARGUS-AUTH-003-172.16.0.5

User 'deploy' successfully logged in from 172.16.0.5 after 3 failed attempts. This may indicate a successful brute-force attack.

**Evidence:**

- `Failed attempts: 3`
- `Successful user: deploy`
- `Source IP: 172.16.0.5`

**Recommendation:** Investigate session for deploy from 172.16.0.5. Check for unauthorized access.

---

### HIGH: Password spraying from 10.0.0.50 (5 users)

**Category:** auth  
**MITRE ATT&CK:** T1110.003  
**ID:** ARGUS-AUTH-002-10.0.0.50

IP 10.0.0.50 attempted login with 5 different usernames: admin, guest, oracle, test, user

**Evidence:**

- `Targeted users: admin, guest, oracle, test, user`

**Recommendation:** Block IP 10.0.0.50 and review targeted accounts.

---

### HIGH: Direct root SSH login from 192.168.1.100

**Category:** auth  
**MITRE ATT&CK:** T1078  
**ID:** ARGUS-AUTH-006-192.168.1.100

Root user logged in directly via SSH from 192.168.1.100. Direct root access should be disabled.

**Evidence:**

- `May 10 09:22:23 server sshd[23456]: Accepted password for root from 192.168.1.100 port 45678 ssh2`

**Recommendation:** Disable root SSH login. Use sudo instead.

---

### MEDIUM: SSH brute-force from 10.0.0.50 (6 failures)

**Category:** auth  
**MITRE ATT&CK:** T1110.001  
**ID:** ARGUS-AUTH-001-10.0.0.50

Detected 6 failed SSH login attempts from 10.0.0.50. This is a potential brute-force attack.

**Evidence:**

- `Failed attempts: 6 from 10.0.0.50`

**Recommendation:** Block IP 10.0.0.50 with: sudo ufw deny from 10.0.0.50

---

### MEDIUM: SSH brute-force from 192.168.1.100 (5 failures)

**Category:** auth  
**MITRE ATT&CK:** T1110.001  
**ID:** ARGUS-AUTH-001-192.168.1.100

Detected 5 failed SSH login attempts from 192.168.1.100. This is a potential brute-force attack.

**Evidence:**

- `Failed attempts: 5 from 192.168.1.100`

**Recommendation:** Block IP 192.168.1.100 with: sudo ufw deny from 192.168.1.100

---

### MEDIUM: New user created: backdoor

**Category:** auth  
**MITRE ATT&CK:** T1136.001  
**ID:** ARGUS-AUTH-004-backdoor

A new user account 'backdoor' was created. Verify this was an authorized action.

**Evidence:**

- `May 10 11:30:22 server useradd[45678]: new user: name=backdoor, UID=1005, GID=1005, home=/home/backdoor, shell=/bin/bash`

**Recommendation:** Verify user 'backdoor' was created intentionally.

---

### MEDIUM: Login attempts for 5 non-existent users

**Category:** auth  
**MITRE ATT&CK:** T1110  
**ID:** ARGUS-AUTH-008

Detected login attempts targeting 5 users that do not exist: admin, test, user, guest, oracle

**Evidence:**

- `admin: 2 attempts`
- `test: 1 attempts`
- `user: 1 attempts`
- `guest: 1 attempts`
- `oracle: 1 attempts`

**Recommendation:** Review source IPs and consider blocking.

---

## Recommended Actions

1. Investigate session for root from 192.168.1.100. Check for unauthorized access.
2. Investigate session for deploy from 172.16.0.5. Check for unauthorized access.
3. Block IP 10.0.0.50 and review targeted accounts.
4. Disable root SSH login. Use sudo instead.
5. Block IP 10.0.0.50 with: sudo ufw deny from 10.0.0.50
6. Block IP 192.168.1.100 with: sudo ufw deny from 192.168.1.100
7. Verify user 'backdoor' was created intentionally.
8. Review source IPs and consider blocking.
