---
name: cloud-iam-audit
description: Audits cloud infrastructure, container configurations, and IAM policies for least-privilege enforcement.
---

# Cloud Security & IAM Least-Privilege Audit

This skill provides methodologies for identifying overprivileged access and container misconfigurations.

## Audit Checklist

### 1. Cloud & AWS IAM Policies
- **Wildcard Admin Rights:** Flag statements containing `"Action": "*"` and `"Resource": "*"`.
- **Privilege Escalation Risks:** Inspect permissions for dangerous primitives:
  - `iam:PassRole`
  - `iam:AttachRolePolicy`
  - `iam:CreatePolicyVersion`
  - `iam:PutUserPolicy`
- **Resource Constraints:** Ensure S3 buckets, KMS keys, and databases specify explicit ARNs instead of `*`.

### 2. Container Hardening (CIS Docker Benchmarks)
- **Non-Root Execution:** Verify the presence of a non-root `USER` instruction.
- **Base Image Pinning:** Require immutable SHA256 digests or specific version tags instead of `:latest`.
- **Secret Hygiene:** Ensure secrets are never injected via `ENV` or `ARG` directives.
- **Blind Execution:** Avoid piped installations like `curl | sh`.

## Executable MCP Tools Available:
- `audit_dockerfile`: Automatically scans Dockerfile for CIS benchmark violations.
- `audit_iam_policy`: Scans IAM policy JSON for wildcard access and privilege escalation paths.
