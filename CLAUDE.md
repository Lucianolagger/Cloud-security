# CLAUDE.md — Cloud-security

## Repository Purpose

This is a **knowledge and resource repository** for cloud penetration testing and security. It contains curated links, tools, exercises, Proof-of-Concept (PoC/ePoC) references, and learning materials covering cloud security — primarily AWS and Azure.

There is no runnable code in this repository. The primary artifact is `README.md`.

## Repository Structure

```
Cloud-security/
└── README.md      # Main resource document — curated tool and link references
```

## Content Organization

`README.md` is organized into the following sections:

| Section | Description |
|---|---|
| Awesome-Cloud-PenTest | Top-level index of cloud pentest resources and training |
| What is AWS / Azure | Official documentation and GitHub doc repos |
| PenTest Policy | Provider-specific pentest authorization policies (AWS, Azure) |
| PenTest in AWS — Offensive | Tools for AWS exploitation, enumeration, and S3 bucket scanning |
| AWS Security — Defensive | Hardening, security assessment, and inventory tools |
| PenTest in Azure — Enumeration | Azure/O365 enumeration and OSINT tools |
| PenTest in Azure — Information Gathering | Azure credential and configuration collection |
| PenTest in Azure — Lateral Movement | Azure AD lateral movement tooling |
| PenTest in Azure — Exploitation | Azure exploitation frameworks |
| Azure — Credential Attacks | Password spraying, MFA bypass, credential dumping |
| Azure Security | Defensive Azure security benchmarks and tools |

## Contribution Conventions

- **Format**: Plain Markdown. Each entry is either a bare URL or `tool-name - description` followed by a URL on the next line.
- **Grouping**: Place new entries under the most relevant existing section. Avoid creating new top-level sections without a clear category need.
- **One URL per line**: External links are listed individually, not inline with prose.
- **No code blocks**: This is a reference/link repository — avoid adding inline code unless introducing a PoC walkthrough.
- **Language**: Section headers and tool descriptions are in English. Portuguese comments are acceptable for personal notes.

## AI Assistant Notes

- This repo has **no build system, test suite, or CI pipeline**. Nothing to run, compile, or install.
- When asked to "add a tool" or "add a resource", insert the entry under the appropriate section in `README.md`, matching the existing list style.
- Verify that links point to legitimate, publicly available security resources (GitHub repos, official vendor docs, known security blogs/research).
- Do **not** add direct exploit payloads, live credentials, or content that violates the provider pentest policies listed in the README.
- The repository author is Joas Antonio dos Santos — active in security research and education (LinkedIn: `joas-antonio-dos-santos`, Twitter/X: `@C0d3Cr4zy`).
- Maintain the existing flat-list Markdown style. Do not restructure into tables or nested lists unless explicitly asked.
- When updating, preserve all existing links — do not remove entries without explicit instruction.

## Related Resources

- AWS penetration testing policy: https://aws.amazon.com/security/penetration-testing/
- Azure penetration testing policy: https://docs.microsoft.com/en-us/azure/security/fundamentals/pen-testing
- Author's curated AWS security tools: https://github.com/toniblyx/my-arsenal-of-aws-security-tools
