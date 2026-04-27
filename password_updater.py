import os
import sys
import logging
import pymysql
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from contextlib import contextmanager

# Load environment variables from .env file
load_dotenv()

# Configure logging for audit trail (ASVS V4 - Access Control)
logging.basicConfig(
    filename='password_update.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Database configuration from environment variables (V6 - Authentication)
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME', 'student_portal_lab_secure')

# Input validation - whitelist of valid usernames
VALID_USERS = {
    "student1",
    "student2",
    "lecturer1",
    "admin1"
}

def validate_username(username):
    """
    Validate username against whitelist (ASVS V1 - Encoding & Sanitization)
    Prevents injection attacks
    """
    if not isinstance(username, str) or len(username) == 0 or len(username) > 50:
        return False
    if username not in VALID_USERS:
        return False
    return True

def validate_password(password):
    """
    Validate password strength (ASVS V6 - Authentication)
    """
    if not isinstance(password, str):
        return False
    if len(password) < 8:
        logging.warning(f"Password validation failed: password too short")
        return False
    if len(password) > 128:
        logging.warning(f"Password validation failed: password too long")
        return False
    return True

@contextmanager
def get_db_connection():
    """
    Secure database connection context manager
    Ensures connections are properly closed
    """
    conn = None
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            autocommit=False,  # Explicit transaction control
            cursorclass=pymysql.cursors.DictCursor,
            charset='utf8mb4'  # Prevent encoding issues
        )
        yield conn
    except pymysql.Error as e:
        logging.error(f"Database connection error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def update_user_password(username, password_hash):
    """
    Update a single user's password hash with proper validation
    (ASVS V6 - Authentication)
    """
    if not validate_username(username):
        logging.warning(f"Invalid username format: {username}")
        return False

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Parameterized query to prevent SQL injection (ASVS V4 - Access Control)
                cur.execute(
                    "UPDATE users SET password_hash=%s, updated_at=NOW() WHERE username=%s",
                    (password_hash, username)
                )
                if cur.rowcount == 0:
                    logging.warning(f"No user found with username: {username}")
                    return False

                conn.commit()
                logging.info(f"Password hash updated successfully for user: {username}")
                return True
    except Exception as e:
        logging.error(f"Error updating password for {username}: {e}")
        return False

def update_passwords_batch(users_dict):
    """
    Update multiple user passwords with error handling
    (ASVS V6 - Authentication, V4 - Access Control)
    """
    if not isinstance(users_dict, dict) or len(users_dict) == 0:
        logging.error("Invalid input: users_dict must be a non-empty dictionary")
        return False

    success_count = 0
    failed_users = []

    for username, password in users_dict.items():
        # Validate inputs before processing (ASVS V1 - Encoding & Sanitization)
        if not validate_username(username):
            logging.warning(f"Skipping user {username}: invalid username format")
            failed_users.append(username)
            continue

        if not validate_password(password):
            logging.warning(f"Skipping user {username}: invalid password format")
            failed_users.append(username)
            continue

        try:
            # Generate secure password hash using werkzeug (ASVS V6)
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')

            if update_user_password(username, password_hash):
                success_count += 1
            else:
                failed_users.append(username)
        except Exception as e:
            logging.error(f"Failed to update password for {username}: {e}")
            failed_users.append(username)

    logging.info(f"Batch update completed: {success_count} successful, {len(failed_users)} failed")
    return success_count, failed_users

def main():
    """
    Main function with error handling (ASVS V4 - Access Control)
    """
    try:
        # Check for required environment variables
        if not DB_USER or not DB_PASSWORD:
            logging.error("Missing required environment variables: DB_USER or DB_PASSWORD")
            print("Error: Database credentials not configured. Please set DB_USER and DB_PASSWORD.")
            return 1

        # User data - in production, these should come from secure sources
        # NOT hardcoded in script
        users = {
            "student1": "SecurePassword1!",
            "student2": "SecurePassword2!",
            "lecturer1": "LecturerPass1!",
            "admin1": "AdminPass123!"
        }

        logging.info("Starting batch password hash update process")
        success_count, failed_users = update_passwords_batch(users)

        if failed_users:
            print(f"Warning: Password update failed for users: {', '.join(failed_users)}")
            logging.warning(f"Failed users: {failed_users}")
            return 1

        print(f"✓ Password hashes updated successfully for all {success_count} users.")
        logging.info("Password hash update process completed successfully")
        return 0

    except Exception as e:
        logging.critical(f"Unexpected error in main: {e}")
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
