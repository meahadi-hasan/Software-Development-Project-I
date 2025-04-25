# Secure National ID Management System

## 📌 Overview
The *Secure National ID Management System* is a C-based software designed to manage national identification records securely. 
It allows administrators to register, update, search, and delete citizen records while maintaining an audit log for transparency. 
The system incorporates encryption techniques for secure password storage and authentication.

## 📑 Features
- *Citizen Management*: Register, update, search, and delete citizen records.
- *Unique NID Generation*: Automatically assigns a unique National ID (NID) to each citizen.
- *Role-Based Access*: Supports different user roles (Admin).
- *Secure Authentication*: Uses SHA-256 hashing with salt for password security.
- *Audit Logging*: Tracks all operations performed on citizen records.
- *Validation Checks*: Ensures correct input formats for date, gender, and blood group.

## 🛠 Technologies Used
- *Programming Language*: C
- *Cryptography*: OpenSSL (SHA-256, PBKDF2, Secure Random Salt)
- *Data Structures*: Structs for user, citizen, and audit logs
- *File Handling*: (Optional) Future enhancement for persistent storage

## 🚀 Installation (Ubuntu/Linux)

### Prerequisites

sudo apt update
sudo apt install build-essential libssl-dev libsqlite3-dev

## Compilation & Execution

# Clone repository
git clone https://github.com/meahadi-hasan/Software-Development-Project-I.git
cd Software-Development-Project-I

# Compile with security flags
gcc national_id_system.c -o nid_system -lcrypto -lsqlite3 -Wall -Wextra -O2

# Run the system
./nid_system
   
## 🔐 User Roles & Authentication
- *Admin*: Full access to all operations.
- *Officer*: Limited access to citizen data.
- *Auditor*: Can view audit logs.


## 📋 Future Enhancements
- Implementing file-based storage or database integration.
- Web or GUI-based interface for better usability.
- Multi-level authentication with OTP verification.
- More granular role permissions and logging improvements.


---
📌 *Developed by: Neural Scope*

*Contributors:*
- Md. Meahadi Hasan
- Md. Sohanur Rahman
- Arafat Rahman
