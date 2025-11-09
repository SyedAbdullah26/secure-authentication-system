# secure-authentication-system

`auth.py` is a Python module designed to handle user authentication in applications. It provides a secure, modular way to manage user registration, login, and access control. With this system, developers can implement password validation, credential storage, and session management without starting from scratch.

---

### Week 7 – Secure Authentication System

**Student Name:** Syed Abdullah  
**Student ID:** M01051411  
**Course:** CST1510 – Programming for Data Communication and Networks  
**Project:** Multi-Domain Intelligence Platform

---

## Project Overview

This project implements a **secure command-line authentication system** in Python, using the `bcrypt` library for hashing and verifying passwords.

It demonstrates modern authentication practices such as password hashing with salts, account lockout after failed login attempts, session management, and input validation — all using a simple file-based system.

The code is structured to resemble real-world authentication systems while remaining efficient, modular, and easy to extend.

---

## Features

| Feature | Description |
|---------|-------------|
| **Secure Password Hashing** | Uses `bcrypt` to hash passwords with automatic salt generation. |
| **User Registration & Login** | Supports multiple user accounts with persistent storage. |
| **Username & Password Validation** | Enforces rules for length, format, and complexity. |
| **Password Strength Meter** | Rates passwords as Weak, Medium, or Strong. |
| **User Roles** | Supports roles such as `user`, `admin`, and `analyst`. |
| **Account Lockout** | Locks accounts for 5 minutes after 3 failed login attempts. |
| **Session Management** | Generates secure session tokens for logged-in users. |
| **File-Based Persistence** | Stores user data, failed attempts, and sessions in local files. |
| **Optimized Logic** | Efficient file handling, reusable functions, and clear typing. |

---

## Design Philosophy

This system is built with **security, readability, and maintainability** in mind.

- Each function has a clear responsibility and includes inline comments explaining both *how* and *why*.  
- Minimizes unnecessary file reads and writes.  
- Lockout settings and other constants are easy to modify.  
- Uses Python typing (`: str`, `-> bool`) for clarity.  
- Follows secure coding practices for file handling and input validation.  
- Provides helpful feedback and error messages for users.

---

## How It Works

**1. Registration**  
- Users enter a username, password, and optional role.  
- Passwords are validated and hashed using `bcrypt`.  
- Details are saved to `users.txt` in a safe format.

**2. Login**  
- The system verifies credentials against stored hashes.  
- If a password is entered incorrectly 3 times, the account locks for 5 minutes.  
- On successful login, a secure session token is created and stored in `sessions.txt`.

**3. File Handling**  
- All data (users, failed attempts, sessions) is stored in plaintext CSV-style files for simplicity.  
- Files are safely read and written using Python context managers.
