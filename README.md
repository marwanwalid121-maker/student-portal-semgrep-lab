# Secure Password Updater Script

## Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables
The `.env` file is already configured with:
- `DB_HOST`: Database host (localhost)
- `DB_USER`: Database user (labuser)
- `DB_PASSWORD`: Database password (labpass123)
- `DB_NAME`: Database name (student_portal_lab_secure)

⚠️ **IMPORTANT:** In production, change these credentials immediately!

### 3. Run the Script
```bash
python password_updater.py
```

### 4. Check Audit Logs
The script generates a `password_update.log` file containing all operations.

## Security Features

✅ **Credential Protection**: All credentials loaded from `.env` file, not hardcoded
✅ **Input Validation**: Username whitelist and password strength validation
✅ **SQL Injection Prevention**: Parameterized queries throughout
✅ **Secure Hashing**: PBKDF2-SHA256 password hashing
✅ **Error Handling**: Comprehensive exception handling and logging
✅ **Audit Trail**: All operations logged to `password_update.log`
✅ **Transaction Control**: Explicit database transaction management

## OWASP ASVS Compliance

- **V1**: Input encoding & sanitization ✓
- **V4**: Access control & API security ✓
- **V5**: File handling (not used in this script)
- **V6**: Authentication & password security ✓
- **V8**: Authorization (scope: profile/account updates)

## MITRE ATT&CK Mitigation

- **T1110 (Brute Force)**: Account lockout via database
- **T1589 (Credential Harvesting)**: No username enumeration
- **T1078 (Valid Accounts)**: Secure credentials storage
- **T1059 (Command Injection)**: Input validation & parameterized queries

## File Structure
```
lab6/
├── password_updater.py      # Main script
├── .env                     # Environment variables (KEEP SECURE)
├── requirements.txt         # Python dependencies
├── README.md               # This file
└── password_update.log     # Generated audit log
```

## Usage Example
```python
python password_updater.py
```

Output:
```
✓ Password hashes updated successfully for all 4 users.
```

## Logs Location
- Audit logs: `password_update.log`
- Check logs for any errors or warnings

## Notes
- The script never displays actual passwords
- All database operations use parameterized queries
- Connection failures are logged but handled gracefully
- Failed updates are tracked and reported
