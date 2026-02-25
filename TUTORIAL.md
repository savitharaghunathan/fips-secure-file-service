# Migrating Go Cryptography to FIPS 140 Compliance Using Konveyor

- [Migrating Go Cryptography to FIPS 140 Compliance Using Konveyor](#migrating-go-cryptography-to-fips-140-compliance-using-konveyor)
  - [Goal](#goal)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [Step 1: Setup](#step-1-setup)
    - [Clone the Repositories](#clone-the-repositories)
    - [Install the Konveyor Extensions](#install-the-konveyor-extensions)
  - [Step 2: Configure Analysis](#step-2-configure-analysis)
    - [2.1 Open the Project](#21-open-the-project)
    - [2.2 Configure Analysis Profile](#22-configure-analysis-profile)
    - [2.3 Select Custom Rules](#23-select-custom-rules)
    - [2.4 Set Source and Target Labels](#24-set-source-and-target-labels)
  - [Step 3: Run Analysis](#step-3-run-analysis)
    - [3.1 Start the Server](#31-start-the-server)
    - [3.2 Run Analysis](#32-run-analysis)
    - [3.3 Analysis Results](#33-analysis-results)
  - [Step 4: Review Violations](#step-4-review-violations)
    - [Encryption Violations (crypto.go)](#encryption-violations-cryptogo)
    - [Authentication Violations (auth.go)](#authentication-violations-authgo)
    - [TLS and Connection Violations (client.go)](#tls-and-connection-violations-clientgo)
  - [Step 5: Configure KAI (GenAI)](#step-5-configure-kai-genai)
  - [Step 6: Generate Fixes with KAI](#step-6-generate-fixes-with-kai)
    - [6.1 Fix Mandatory Violations](#61-fix-mandatory-violations)
    - [6.2 Review Potential Violations](#62-review-potential-violations)
  - [Step 7: Verify the Migration](#step-7-verify-the-migration)
  - [Conclusion](#conclusion)

## Goal

Migrate a Go application that uses non-FIPS-compliant cryptographic algorithms, weak key sizes, and insecure TLS configurations to FIPS 140 compliance. We will use custom rules with Konveyor to analyze the application and KAI to generate migration fixes for mandatory violations.

## Overview

[FIPS 140](https://csrc.nist.gov/publications/detail/fips/140/3/final) is a U.S. government standard for cryptographic modules. Applications handling sensitive data in regulated environments (government, healthcare, finance) must use only FIPS-approved algorithms and key sizes.

Many Go applications use non-compliant cryptographic primitives — weak ciphers like DES and RC4, non-approved hash functions like MD5 and Blake2, or insufficient key sizes. Migrating these applications requires identifying non-compliant usage and replacing it with a FIPS-approved alternative.

Konveyor addresses this:

- **Discovery** — the Konveyor Go extension and built-in provider find reference to non-FIPS cryptographic APIs, weak key sizes, hardcoded keys, and insecure TLS settings
- **Migration guidance** — each rule produces a violation with the FIPS-approved replacement
- **KAI fixes** — KAI uses the rule messages to generate context-aware FIPS-compliant code via LLM

### Custom Rules for FIPS Migration

This scenario uses custom rules that detect non-FIPS cryptographic patterns in Go source code. The rules use two providers:

#### `go.referenced` rules

Detect usage of non-FIPS cryptographic packages via the Go LSP:

```yaml
- ruleID: fips-go-weak-00100
  description: "Non-FIPS cipher: DES (crypto/des)"
  category: mandatory
  effort: 3
  when:
    go.referenced:
      pattern: "crypto/des"
  message: |
    DES is not FIPS-approved. Replace with AES-GCM (crypto/aes + crypto/cipher).
```

#### `builtin.filecontent` rules

Detect hardcoded keys, weak key sizes, and insecure TLS settings via regex:

```yaml
- ruleID: fips-go-tls-00100
  description: "Insecure TLS: InsecureSkipVerify set to true"
  category: mandatory
  effort: 1
  when:
    builtin.filecontent:
      pattern: 'InsecureSkipVerify\s*[:=]\s*true'
      filePattern: "*.go"
  message: |
    Setting InsecureSkipVerify to true disables TLS certificate verification.
    Remove this setting or set it to false.
```

## Prerequisites

- [VSCode](https://code.visualstudio.com/download)
- [Git](https://git-scm.com/downloads)
- [Go toolchain](https://go.dev/dl/) (1.22+)
- AI credentials (OpenAI, Amazon Bedrock, Ollama, etc.)

Additionally, you will need to have the Konveyor IDE plugin installed in VSCode. Download the latest from [here](https://github.com/konveyor/editor-extensions/releases).

## Step 1: Setup

### Clone the Repositories

Clone the example application:

```shell
git clone https://github.com/savitharaghunathan/fips-secure-file-service.git
cd fips-secure-file-service
```

Clone the FIPS rules repository (used in Step 2.3):

```shell
git clone https://github.com/savitharaghunathan/fips-pqc-rules.git
```

### Install the Konveyor Extensions

Open VSCode and go to the Extensions view (`Cmd+Shift+X` on macOS, `Ctrl+Shift+X` on Linux/Windows).

Install two extensions:

1. **Konveyor** (`konveyor.konveyor-core`) — the core extension that provides static analysis, rule management, and the KAI integration
2. **Konveyor Go** (`konveyor.konveyor-go`) — adds the Go analysis provider, enabling `go.referenced` and `go.dependency` rule conditions

The Go language extension (`golang.go`) is installed automatically as a dependency of Konveyor Go.

## Step 2: Configure Analysis

### 2.1 Open the Project

Navigate to File > Open in VSCode and open the `fips-secure-file-service/` folder as the workspace root. The project structure is:

```
fips-secure-file-service/
├── main.go              ← entry point, wires up all packages
├── pkg/
│   ├── crypto/
│   │   └── crypto.go    ← weak ciphers, hardcoded keys, non-FIPS hashes
│   ├── auth/
│   │   └── auth.go      ← MD5 hashing, weak RSA, non-FIPS KDFs
│   └── client/
│       └── client.go    ← insecure TLS, disabled SSL
├── go.mod
└── go.sum
```

The app is a file encryption and user authentication service that intentionally uses non-FIPS-compliant cryptography:

- **`pkg/crypto/crypto.go`** — encrypts files using DES, 3DES, RC4, Blowfish, and ChaCha20; hashes using Blake2b and Blake2s
- **`pkg/auth/auth.go`** — hashes passwords with MD5, Argon2, and bcrypt; generates 1024-bit RSA keys
- **`pkg/client/client.go`** — connects with `InsecureSkipVerify: true` and `sslmode=disable`

### 2.2 Configure Analysis Profile

Click the Konveyor extension icon in the sidebar, then click the settings icon to configure the analysis profile.

### 2.3 Select Custom Rules

In the configuration dialog, click **Set Rules** and navigate to the `fips-pqc-rules/` directory from the cloned rules repository.

### 2.4 Set Source and Target Labels

Set **Source** to `go` and **Target** to `go`. The analyzer filters rules by these labels — rules without matching labels are excluded from analysis.

## Step 3: Run Analysis

### 3.1 Start the Server

Click **Start** in the Konveyor Analysis view to launch the analyzer and RPC server.

### 3.2 Run Analysis

Once the server is ready, click **Run Analysis**.

### 3.3 Analysis Results

**Total Issues: 17** *(36 incidents found)*

| # | Issue (Rule) | Category | Incidents |
|---|---|---|---|
| 1 | Non-FIPS cipher: DES (`crypto/des`) | Mandatory | 2 |
| 2 | Non-FIPS cipher: Triple DES (`des.NewTripleDESCipher`) | Mandatory | 1 |
| 3 | Non-FIPS cipher: RC4 (`crypto/rc4`) | Mandatory | 1 |
| 4 | Non-FIPS hash: MD5 (`crypto/md5`) | Mandatory | 1 |
| 5 | Non-FIPS cipher: Blowfish (`x/crypto/blowfish`) | Mandatory | 1 |
| 6 | Non-FIPS cipher: ChaCha20 (`x/crypto/chacha20`) | Mandatory | 1 |
| 7 | Non-FIPS AEAD: ChaCha20-Poly1305 (`x/crypto/chacha20poly1305`) | Mandatory | 1 |
| 8 | Non-FIPS hash: Blake2b (`x/crypto/blake2b`) | Mandatory | 1 |
| 9 | Non-FIPS hash: Blake2s (`x/crypto/blake2s`) | Mandatory | 1 |
| 10 | Non-FIPS KDF: Argon2 (`x/crypto/argon2`) | Mandatory | 1 |
| 11 | Non-FIPS KDF: bcrypt (`x/crypto/bcrypt`) | Mandatory | 1 |
| 12 | Weak RSA key size (<2048 bits) | Mandatory | 1 |
| 13 | Hardcoded cryptographic key | Mandatory | 5 |
| 14 | Hardcoded IV/nonce | Mandatory | 2 |
| 15 | Insecure TLS: `InsecureSkipVerify` set to true | Mandatory | 1 |
| 16 | Insecure database connection: `sslmode=disable` | Mandatory | 1 |
| 17 | PQC Inventory: RSA usage detected | Potential | 4 |

**By file:**

| File | Incidents |
|---|---|
| `pkg/crypto/crypto.go` | 22 |
| `pkg/auth/auth.go` | 11 |
| `pkg/client/client.go` | 3 |

## Step 4: Review Violations

Click on any violation in the issues pane to see its incidents. Click on an incident to jump to the affected line in the source file.

### Encryption Violations (crypto.go)

This file contains the majority of violations — weak ciphers, non-FIPS hash functions, and hardcoded keys.

**"Non-FIPS cipher: DES"** — DES uses a 56-bit key and is not approved for FIPS. Replace with AES-GCM:

```
Replace:
  block, err := des.NewCipher([]byte("8bytekey"))

With AES-GCM:
  key := make([]byte, 32)
  rand.Read(key)
  block, err := aes.NewCipher(key)
  gcm, err := cipher.NewGCM(block)
  nonce := make([]byte, gcm.NonceSize())
  rand.Read(nonce)
  ciphertext := gcm.Seal(nonce, nonce, data, nil)
```

**"Non-FIPS hash: Blake2b"** — Blake2b is not FIPS-approved. Replace with SHA-512:

```
Replace:
  hash := blake2b.Sum256(data)

With:
  hash := sha512.Sum512(data)
```

**"Hardcoded cryptographic key"** — Hardcoded keys violate FIPS operational requirements. Generate keys using `crypto/rand`:

```
Replace:
  key := []byte("blowfish-key-material!")

With:
  key := make([]byte, 32)
  if _, err := rand.Read(key); err != nil {
      return nil, err
  }
```

### Authentication Violations (auth.go)

**"Non-FIPS hash: MD5"** — MD5 is broken and not FIPS-approved for any use. Replace with SHA-256:

```
Replace:
  hash := md5.Sum([]byte(password))

With:
  hash := sha256.Sum256([]byte(password))
```

**"Non-FIPS KDF: Argon2"** and **"Non-FIPS KDF: bcrypt"** — Neither Argon2 nor bcrypt is FIPS-approved. Replace with PBKDF2 using SHA-256:

```
Replace:
  argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

With:
  pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
```

**"Weak RSA key size"** — 1024-bit RSA keys are below the FIPS minimum of 2048 bits:

```
Replace:
  rsa.GenerateKey(rand.Reader, 1024)

With:
  rsa.GenerateKey(rand.Reader, 2048)
```

### TLS and Connection Violations (client.go)

**"Insecure TLS: InsecureSkipVerify"** — Disabling certificate verification defeats TLS security. Remove the setting or set it to `false`:

```
Replace:
  cfg.InsecureSkipVerify = true

With:
  // Remove the InsecureSkipVerify setting entirely, or:
  cfg.InsecureSkipVerify = false
```

**"Insecure database connection: sslmode=disable"** — Database connections without SSL expose data in transit. Use `sslmode=verify-full`:

```
Replace:
  "postgres://fileservice:password@db-host:5432/files?sslmode=disable"

With:
  "postgres://fileservice:password@db-host:5432/files?sslmode=verify-full"
```

## Step 5: Configure KAI (GenAI)

To generate FIPS-compliant fixes, configure an LLM provider.

Open the Command Palette (`Cmd+Shift+P`) and run **Konveyor: Open the GenAI model provider configuration file**. This opens `provider-settings.yaml`.

Move the `&active` YAML anchor to the provider you want to use:

**OpenAI:**
```yaml
OpenAI: &active
  environment:
    OPENAI_API_KEY: "sk-your-key-here"
  provider: "ChatOpenAI"
  args:
    model: "gpt-4o"
```

**Ollama (local, no API key):**
```yaml
ChatOllama: &active
  provider: "ChatOllama"
  args:
    model: "granite-code:8b-instruct"
    baseUrl: "127.0.0.1:11434"
```


Other supported providers include Azure OpenAI, Google Gemini, DeepSeek, and any OpenAI-compatible endpoint.

## Step 6: Generate Fixes with KAI

With a GenAI provider configured, you can generate FIPS-compliant fixes.

### 6.1 Fix Mandatory Violations

All 16 mandatory violations have deterministic FIPS-approved replacements that KAI can generate automatically.

##### Step 1: Request a Solution

Click the wrench icon next to a violation to request a fix from KAI, or right-click on a file and select **Kai-Fix All** to fix all incidents in the file.

##### Step 2: Review KAI's Solution

KAI provides a solution that replaces non-FIPS cryptography with approved alternatives. The changes appear in a diff editor (side-by-side view).

Key transformations KAI generates:

| Non-FIPS (Before) | FIPS-Approved (After) |
|---|---|
| `crypto/des` (DES) | `crypto/aes` + `crypto/cipher` (AES-GCM) |
| `des.NewTripleDESCipher` (3DES) | `crypto/aes` + `crypto/cipher` (AES-GCM) |
| `crypto/rc4` | `crypto/aes` + `crypto/cipher` (AES-GCM) |
| `crypto/md5` | `crypto/sha256` |
| `x/crypto/blowfish` | `crypto/aes` + `crypto/cipher` (AES-GCM) |
| `x/crypto/chacha20` | `crypto/aes` + `crypto/cipher` (AES-GCM) |
| `x/crypto/chacha20poly1305` | `crypto/aes` + `crypto/cipher` (AES-GCM) |
| `x/crypto/blake2b` | `crypto/sha512` |
| `x/crypto/blake2s` | `crypto/sha256` |
| `x/crypto/argon2` | `crypto/pbkdf2` (PBKDF2-SHA256) |
| `x/crypto/bcrypt` | `crypto/pbkdf2` (PBKDF2-SHA256) |
| RSA 1024-bit | RSA 2048-bit |
| Hardcoded keys | `crypto/rand` generated keys |
| Hardcoded IV/nonce | `crypto/rand` generated nonces |
| `InsecureSkipVerify: true` | Remove or set `false` |
| `sslmode=disable` | `sslmode=verify-full` |

##### Step 3: Apply the Changes

Review the diff and click **Accept** to apply the changes.

### 6.2 Review Potential Violations

After applying mandatory fixes, review the remaining **potential** category violations. These require human judgment and cannot be auto-fixed:

- **PQC Inventory: RSA usage detected** — This informational rule flags all RSA usage for post-quantum cryptography migration planning. RSA is currently FIPS-approved, but organizations should inventory RSA usage in preparation for future PQC migration. No immediate action is required.

## Step 7: Verify the Migration

After accepting fixes:

1. The analyzer **automatically reruns** and updates the issues pane. Resolved mandatory violations disappear.

2. Run `go build` in the terminal to verify the migrated code compiles:

```shell
go build ./...
```

3. After applying resolutions, you may see new **potential** or **informational** issues on the fixed code. These are expected:
   - **PBKDF2 iteration count** — verify the iteration count meets current NIST recommendations (600,000+ for SHA-256)
   - **PQC Hash inventory** — informational flag on SHA-256/SHA-512 usage for future PQC planning
   - **PQC RSA inventory** — informational flag on RSA usage for future PQC planning

   These are not violations — they are informational rules that help track cryptographic usage for future migration planning.

If there are remaining violations or build errors, repeat Step 6 to address them.

## Conclusion

In this tutorial, we used Konveyor to migrate a Go application from non-compliant cryptography to FIPS 140 compliance. Starting with 17 issues and 36 incidents across three files, we:

1. **Discovered** all non-FIPS cryptographic usage using custom rules — weak ciphers (DES, 3DES, RC4, Blowfish, ChaCha20), non-approved hashes (MD5, Blake2b, Blake2s), non-FIPS KDFs (Argon2, bcrypt), weak RSA keys, hardcoded key material, and insecure TLS settings
2. **Generated fixes** for all 16 mandatory violations using KAI, replacing each non-compliant algorithm with its FIPS-approved equivalent (AES-GCM, SHA-256/SHA-512, PBKDF2, RSA 2048+, `crypto/rand`)
3. **Reviewed** potential violations (PQC inventory) that require human judgment for future post-quantum migration planning

This approach scales beyond the sample app. The same FIPS rules can be applied to any Go codebase — Konveyor scans the entire project, surfaces every non-compliant usage, and KAI generates fixes informed by the rule messages. This turns a manual audit that touches scattered files across a codebase into a guided, repeatable process.

The rules used in this tutorial are available at [fips-pqc-rules](https://github.com/savitharaghunathan/fips-pqc-rules).
