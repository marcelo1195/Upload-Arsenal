# Upload-Arsenal: Advanced File Upload Test Suite

Upload-Arsenal is a command-line tool built with Python 3, designed to generate a comprehensive suite of payloads for security testing of file upload functionalities. It was created to assist security researchers, pentesters, and bug bounty hunters in efficiently auditing systems and uncovering complex vulnerabilities.

The tool generates everything from simple proofs-of-concept to advanced, obfuscated exploits, including reverse shells and polyglots, to bypass common security measures.

## ✨ Features

- **Multi-Language Support:** Generates payloads for `PHP`, `Java`, `Python`, `Ruby`, and `Node.js`.
- **Diverse Attack Vectors:**
    - **Proof-of-Concept (PoC):** Non-intrusive files that safely confirm code execution.
    - **Command Injection (RCE):** Payloads that allow command execution via URL parameters.
    - **Reverse Shells:** Interactive and non-interactive payloads to gain a shell on the target.
    - **XXE (XML External Entity):** Files to test for XML processing vulnerabilities.
    - **XSS in SVG:** Cross-Site Scripting payloads embedded in SVG files.
- **Advanced Bypass Techniques:**
    - **Code Obfuscation:** Implements multiple layers of obfuscation to evade signature-based detection.
    - **Polyglots:** Generates files that are valid in two formats simultaneously (e.g., a PNG that is also a PHP shell).
- **Fuzzing Wordlists:**
    - Generates lists of file extension variations for filter bypass.
    - Generates a comprehensive list of image MIME types to test `Content-Type` validation.

## 🔬 Generated Files Explained

Upload-Arsenal creates several types of files, each with a specific purpose, catering to different phases of security testing.

### Proof-of-Concept (PoC) Files
- **Purpose:** Designed for **Bug Bounty** programs and safe vulnerability validation.
- **Behavior:** These files are non-intrusive and only execute a harmless action, like printing a confirmation message (e.g., `echo "File upload vulnerability detected!"`). This proves code execution is possible without causing any damage, which is often a requirement for bounty submissions.

### Exploit Files
- **Purpose:** Designed for **Penetration Testing** and **CTF challenges** where active exploitation is permitted.
- **Types:**
    - **Command Injection (`exploit_*.`):** Provides a simple Remote Code Execution (RCE) vector, usually via a URL parameter (e.g., `.../shell.php?cmd=whoami`).
    - **Reverse Shells (`revshell_*.`):** Establishes an interactive or non-interactive shell from the target server back to the attacker's machine, providing persistent access. The tool generates multiple variants to increase the chances of success in hardened environments.

### Obfuscated Payloads
- **Purpose:** To bypass Web Application Firewalls (WAFs) and other signature-based security products.
- **Techniques Used:** The `-obfuscate` flag applies several randomized techniques to make the payload unrecognizable to common security filters. This includes:
    - **Multi-layer encoding** (Base64, Gzip, Hex, Octal).
    - **String manipulation** (`str_rot13`, `strrev`).
    - **Dynamic generation** of variable and function names.
    - **Execution via alternative functions** (`assert`, `create_function`, variable functions) to avoid blacklisted keywords like `eval()` and `system()`.

### Advanced Bypass Files & Wordlists
- **Polyglots (`polyglot.*`):** These are structurally valid files of one type (e.g., PNG) that also contain a valid payload of another type (e.g., PHP). They are designed to defeat deep file inspection and content validation checks.
- **Wordlists:** These are not payloads themselves but are meant to be used with fuzzing tools like **Burp Intruder**. They help discover bypasses by testing hundreds of variations of filenames (using null bytes, special characters, case mangling) and `Content-Type` headers.

## 🚀 Installation & Usage

Upload-Arsenal is written in pure Python 3 and requires no external dependencies.

```bash
# 1. Clone the repository
git clone [https://github.com/marcelo1195/Upload-Arsenal.git](https://github.com/marcelo1195/Upload-Arsenal.git)

# 2. Navigate to the directory
cd Upload-Arsenal

# 3. Run the script to see the help menu
python3 arsenal.py -h
```

### Usage Examples

**1. Generate all non-intrusive Proof-of-Concept (PoC) files:**
```bash
python3 arsenal.py -poc
```

**2. Generate all command injection exploit files and obfuscate them:**
```bash
python3 arsenal.py -exploit -obfuscate
```

**3. Generate all reverse shell payloads for a listener on `10.10.14.5:4444`:**
```bash
python3 arsenal.py --rev-shell --lhost 10.10.14.5 --lport 4444
```

**4. Generate a full suite with all possible payloads, all obfuscated:**
```bash
python3 arsenal.py -poc -exploit --rev-shell --lhost 10.0.0.1 --lport 9001 -obfuscate
```

## 📜 License

This project is licensed under the **GNU General Public License v3.0**.

This means you are free to use, study, share, and modify the software. However, if you distribute a modified version, it **must** also be licensed under the GPL-3.0, ensuring the code remains open-source for the community. You can find the full license text in the `LICENSE` file.
.