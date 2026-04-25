# Security Policy

## Supported Versions

Only the latest release of **tabular** receives security updates and fixes. Previous
versions are **not** maintained and may contain known vulnerabilities.

| Version  | Supported |
| -------- | --------- |
| latest   | ✅ |
| < latest | ❌ |

---

## Reporting a Vulnerability

> [!CAUTION]
> If you discover a security vulnerability, **do not** open a public issue. 
> Instead, please contact the maintainer directly by submitting
> [_private_ advisory](https://github.com/LeShaunJ/tabular/security/advisories/new).

Please include as much detail as possible:

- [ ] A description of the issue and its potential impact  
- [ ] Steps to reproduce (_if applicable_)  
- [ ] Any suggested mitigations or fixes

You’ll receive a confirmation within **72 hours**, and we’ll aim to provide a fix within **7 days** of validation.

---

## Disclosure Policy

After a fix is released, a public advisory may be published summarizing:

- The nature of the vulnerability  
- The affected versions  
- The mitigation or patch details  

Researchers who responsibly disclose vulnerabilities will be credited in the advisory.

---

## Security Best Practices for Users

- Always verify the integrity of downloaded shards and dependencies.  
- Keep your Crystal compiler and dependencies up to date.  
- Avoid running untrusted or modified versions of **tabular** in production.  
- Review your dependency tree regularly for outdated or vulnerable libraries.

---

Maintainer: [@LeShaunJ](https://github.com/LeShaunJ)
