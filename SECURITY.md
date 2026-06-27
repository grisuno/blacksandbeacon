# Security Policy

## Supported Versions

Black Sand Beacon is actively developed. Only the latest release receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest| :x:                |

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in Black Sand Beacon, please report it responsibly:

1. Email the maintainers at the address listed in the project's README or GitHub profile.
2. Include a detailed description of the vulnerability, steps to reproduce, and any potential impact.
3. Allow reasonable time (typically 90 days) for the maintainers to address the issue before public disclosure.

We will acknowledge receipt of your report within 48 hours and provide an estimated timeline for a fix.

## Security Considerations

### Cryptography

Black Sand Beacon uses AES-256-CFB for encrypting C2 traffic. The AES key is stored in `config/config.json` and **must never be committed to version control**. The file is excluded via `.gitignore`.

**Known limitation**: AES-CFB does not provide message authentication. An attacker with network access could potentially modify encrypted commands in transit. Mitigation strategies:
- Use TLS (set `network.verify_tls: true` in config)
- Implement HMAC (future enhancement)
- Deploy on isolated networks

### Beacon Deployment

Beacons are designed to run on target systems during authorized red team engagements. Ensure you have explicit written authorization before deploying beacons to any system you do not own.

### Configuration Security

- Never commit `config/config.json` to version control
- Use strong, randomly generated AES keys (32 bytes / 64 hex characters)
- Restrict file permissions: `chmod 600 config/config.json`
- Rotate keys regularly and after each engagement

## Responsible Use

Black Sand Beacon is intended for authorized security testing, red team operations, and educational purposes only. Unauthorized use is illegal and unethical. Always obtain explicit written permission before using this tool against any system.
