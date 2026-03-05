# 🔐 Secure File Exchange System

<p align="left">
  <img src="https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white" alt="Java" />
  <img src="https://img.shields.io/badge/Cryptography-Security-red?style=for-the-badge" alt="Cryptography" />
  <img src="https://img.shields.io/badge/Network-Socket_Programming-blue?style=for-the-badge" alt="Networking" />
</p>

## 📌 Project Overview
The **Secure File Exchange System** is a robust Java-based application designed for the highly secure transmission of files across a network. It implements a multi-layered cryptographic protocol to ensure **Confidentiality**, **Integrity**, and **Authentication**, protecting data against interception and unauthorized modification.

## 📢 Features

**✅ Advanced Hybrid Encryption**
* **Symmetric Encryption:** Utilizes the **Camellia cipher** in **OFB (Output Feedback) mode** for high-speed, secure file encryption.
* **Asymmetric Key Exchange:** Implements the **McEliece cryptosystem** (based on Goppa codes) for the secure delivery of session keys, providing a layer of post-quantum resistance.

**✅ Robust Authentication & Integrity**
* **Digital Signatures:** Integrated **ECDSA (Elliptic Curve Digital Signature Algorithm)** to verify the sender's identity and ensure non-repudiation.
* **Hashing:** Employs **SHA-256** for generating file digests to verify data integrity upon receipt.

**✅ Secure Network Communication**
* Built on a **Client-Server architecture** using Java Sockets for reliable data transfer.
* Implements a custom handshake protocol for identity verification and session key establishment.

## 🛠 Tech Stack

**🖥 Language & Frameworks**
* **Java:** Primary language for backend logic and cryptographic implementation.
* **Bouncy Castle API:** Leveraged for advanced cryptographic primitives and algorithm support.

**⚙️ Cryptographic Algorithms**
* **Camellia (128-bit):** Symmetric data encryption.
* **McEliece:** Public-key infrastructure for key encapsulation.
* **ECDSA:** Digital signatures using elliptic curve cryptography.

## 📐 Cryptographic Pipeline

The system follows a rigorous process to ensure end-to-end security:
1. **Key Generation:** Client generates a session key and encrypts it using the Server's McEliece public key.
2. **Signature:** Client signs the file hash with their ECDSA private key.
3. **Encryption:** The file is encrypted using Camellia-OFB.
4. **Transmission:** The encrypted file, encrypted key, and signature are sent to the server for decryption and verification.



## 📂 Repository Structure
* `src/`: Java source files including Client, Server, and Cryptography modules.
* `docs/`: Technical report and architecture presentation.
* `lib/`: Required cryptographic libraries (e.g., Bouncy Castle).

## 💻 How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/rober-saliba/Secure-File-Exchange.git](https://github.com/rober-saliba/Secure-File-Exchange.git)
2.Add Dependencies: Ensure the Bouncy Castle JAR files are included in your project build path.


3.Run the Server:
 ```bash
java Server
 ```
4.Run the Client:
 ```bash
java Client
 ```
