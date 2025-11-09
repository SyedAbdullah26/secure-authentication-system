# secure-authentication-system
auth.py is a Python module for handling user authentication in applications. It provides a secure and modular way to manage user login, registration, and access control. With this program, developers can implement password validation, user credential storage, and session management without having to build these features from scratch.

\# Week 7 – Secure Authentication System



\*\*Student Name:\*\* Syed Abdullah

\*\*Student ID:\*\* M01051411  

\*\*Course:\*\* CST1510 – Programming for Data Communication and Networks  

\*\*Project:\*\* Multi-Domain Intelligence Platform  



---



\## Project Overview



This project implements a \*\*secure command-line authentication system\*\* built in Python using the `bcrypt` library for password hashing and verification.  

It demonstrates \*\*modern authentication principles\*\* such as password hashing, salted encryption, account lockout, session management, and input validation — all within a simple file-based system.



The code is structured to mimic real-world authentication logic while remaining efficient, modular, and easy to extend.



---



\## Features Implemented



| Feature | Description |

|----------|--------------|

| \*\*Secure Password Hashing\*\* | Uses `bcrypt` to hash passwords with automatic salt generation. |

| \*\*User Registration \& Login\*\* | Supports multiple user accounts with persistent storage. |

| \*\*Username \& Password Validation\*\* | Enforces length, format, and complexity rules for safety. |

| \*\*Password Strength Meter\*\* | Evaluates password strength as Weak, Medium, or Strong. |

| \*\*User Roles\*\* | Supports custom roles: `user`, `admin`, `analyst`. |

| \*\*Account Lockout\*\* | Locks account for 5 minutes after 3 failed login attempts. |

| \*\*Session Management\*\* | Generates secure session tokens for successful logins. |

| \*\*File-Based Data Persistence\*\* | Stores user data, failed attempts, and sessions in local files. |

| \*\*Optimized Logic\*\* | Efficient file handling, clear typing, and reusable helper functions. |



---



\## Design Philosophy



This system was designed with \*\*security, clarity, and maintainability\*\* in mind.  

Each function performs a distinct responsibility and includes \*\*detailed inline documentation\*\* explaining not just \*how\* it works, but \*why\* it’s implemented that way.



Optimizations were made to:

\- Minimize unnecessary file reads/writes.  

\- Use constants for lockout settings for easy modification.  

\- Utilize Python typing (`: str`, `-> bool`) for clarity.  

\- Follow secure coding conventions with safe file handling.  

\- Handle user input gracefully with error checking and feedback.



---



\## How It Works



1\. \*\*Registration:\*\*

&nbsp;  - User enters a username, password, and optional role.

&nbsp;  - Password is validated and hashed using `bcrypt`.

&nbsp;  - User details (`username, hashed\_password, role`) are stored in `users.txt`.



2\. \*\*Login:\*\*

&nbsp;  - The system verifies the user’s credentials against the stored hash.

&nbsp;  - If incorrect passwords are entered 3 times, the account locks for 5 minutes.

&nbsp;  - On successful login, a random session token is created and stored in `sessions.txt`.



3\. \*\*File Handling:\*\*

&nbsp;  - All data (users, failed attempts, sessions) are stored in plaintext CSV-style files for simplicity.

&nbsp;  - Each file is read/written safely using Python’s context managers.
