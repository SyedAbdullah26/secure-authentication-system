# Week 7 Lab – Secure Authentication System
# Course: CST1510 Programming for Data Communication and Networks
# Student: Syed Abdullah

# WHAT DOES IT DO ?

# This program implements a secure user authentication system using bcrypt.
# It allows registration and login, enforces password rules, prevents brute-force
# attempts, and includes advanced features like session tokens and user roles.

import bcrypt 
import os
import secrets
import time

# File constants (used for persistent storage)
USER_DATA_FILE = "users.txt"
FAILED_ATTEMPTS_FILE = "failed_attempts.txt"
SESSION_FILE = "sessions.txt"

# Account lockout configuration
LOCKOUT_LIMIT = 3           # Maximum failed login attempts
LOCKOUT_DURATION = 300      # Lockout time in seconds (5 minutes)


# SECURITY CORE
def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password securely using bcrypt with automatic salt.
    Returns the hashed password as a UTF-8 string.
    """
    password_bytes = plain_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a given plaintext password against a stored hash.
    Returns True if passwords match, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode('utf-8'),
                          hashed_password.encode('utf-8'))


# FILE UTILITIES
def user_exists(username: str) -> bool:
    """
    Check if a username already exists in the user data file.
    """
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, 'r') as f:
        for line in f:
            stored_username, *_ = line.strip().split(',', 2)
            if stored_username == username:
                return True
    return False


def load_failed_attempts() -> dict:
    """
    Load failed login attempts from file into a dictionary.
    Format: {username: (count, last_attempt_time)}
    """
    attempts = {}
    if not os.path.exists(FAILED_ATTEMPTS_FILE):
        return attempts

    with open(FAILED_ATTEMPTS_FILE, 'r') as f:
        for line in f:
            username, count, timestamp = line.strip().split(',')
            attempts[username] = (int(count), float(timestamp))
    return attempts


def save_failed_attempts(attempts: dict):
    """
    Save the failed login attempts dictionary back to file.
    """
    with open(FAILED_ATTEMPTS_FILE, 'w') as f:
        for user, (count, ts) in attempts.items():
            f.write(f"{user},{count},{ts}\n")


# AUTHENTICATION SYSTEM
def register_user(username: str, password: str, role: str = "user") -> bool:
    """
    Register a new user with a hashed password and a role.
    Returns True if registration is successful.
    """
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False

    hashed_pw = hash_password(password)
    with open(USER_DATA_FILE, 'a') as f:
        f.write(f"{username},{hashed_pw},{role}\n")

    print(f"Success: User '{username}' registered as '{role}'.")
    return True


def check_password_strength(password: str) -> str:
    """
    Evaluate password strength as Weak / Medium / Strong based on criteria.
    """
    length = len(password)
    upper = any(c.isupper() for c in password)
    lower = any(c.islower() for c in password)
    digit = any(c.isdigit() for c in password)
    special = any(not c.isalnum() for c in password)

    if length < 6:
        return "Weak"
    if upper and lower and digit and special and length >= 10:
        return "Strong"
    if (upper or lower) and (digit or special):
        return "Medium"
    return "Weak"


def create_session(username: str) -> str:
    """
    Generate and store a unique session token for logged-in users.
    """
    token = secrets.token_hex(16)
    with open(SESSION_FILE, 'a') as f:
        f.write(f"{username},{token},{time.time()}\n")
    return token


def login_user(username: str, password: str) -> bool:
    """
    Authenticate a user and handle lockout for repeated failed attempts.
    """
    if not os.path.exists(USER_DATA_FILE):
        print("Error: No users registered yet.")
        return False

    attempts = load_failed_attempts()
    now = time.time()

    # Check for account lockout
    if username in attempts:
        count, last_try = attempts[username]
        if count >= LOCKOUT_LIMIT and now - last_try < LOCKOUT_DURATION:
            remaining = int((LOCKOUT_DURATION - (now - last_try)) / 60)
            print(f"Account locked. Try again in {remaining} minutes.")
            return False

    with open(USER_DATA_FILE, 'r') as f:
        for line in f:
            stored_username, stored_hash, role = line.strip().split(',', 2)
            if stored_username == username:
                # Verify password match
                if verify_password(password, stored_hash):
                    print(f"Login successful! Welcome, {username} ({role}).")
                    token = create_session(username)
                    print(f"Session token: {token}")
                    # Reset failed attempts
                    if username in attempts:
                        del attempts[username]
                    save_failed_attempts(attempts)
                    return True
                else:
                    # Record failed attempt
                    count, _ = attempts.get(username, (0, now))
                    attempts[username] = (count + 1, now)
                    save_failed_attempts(attempts)
                    print("Incorrect password.")
                    if attempts[username][0] >= LOCKOUT_LIMIT:
                        print("Account locked for 5 minutes after 3 failed attempts.")
                    return False

    print("Error: Username not found.")
    return False


# VALIDATION HELPERS 
def validate_username(username: str) -> tuple:
    """
    Validate username format: must be alphanumeric and 3–20 characters long.
    Returns (True, "") if valid or (False, "reason") if invalid.
    """
    if not (3 <= len(username) <= 20) or not username.isalnum():
        return (False, "Username must be 3–20 characters long and alphanumeric.")
    return (True, "")


def validate_password(password: str) -> tuple:
    """
    Validate password length and ensure it meets basic security rules.
    """
    if len(password) < 6:
        return (False, "Password must be at least 6 characters long.")
    if len(password) > 50:
        return (False, "Password too long (max 50 characters).")
    return (True, "")


# MENU INTERFACE
def display_menu():
    """Display the main program options."""
    print("\n" + "=" * 50)
    print("   MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print("       Secure Authentication System")
    print("=" * 50)
    print("[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 50)


def main():
    """
    Main interactive program loop.
    Provides options for user registration and login.
    """
    print("\nWelcome to the Week 7 Secure Authentication System!")

    while True:
        display_menu()
        choice = input("Select an option (1–3): ").strip()

        if choice == "1":
            # User Registration Flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()
            valid, msg = validate_username(username)
            if not valid:
                print("Error:", msg)
                continue

            password = input("Enter a password: ").strip()
            strength = check_password_strength(password)
            print(f"Password Strength: {strength}")
            valid, msg = validate_password(password)
            if not valid:
                print("Error:", msg)
                continue

            confirm = input("Confirm your password: ").strip()
            if password != confirm:
                print("Error: Passwords do not match.")
                continue

            role = input("Enter role (user/admin/analyst) [default=user]: ").strip().lower()
            if not role:
                role = "user"

            register_user(username, password, role)

        elif choice == "2":
            # User Login Flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            login_user(username, password)

        elif choice == "3":
            print("\nThank you for using the authentication system. Goodbye!")
            break

        else:
            print("Invalid option. Please choose between 1–3.")


if __name__ == "__main__":
    main()
