# Cloud Infrastructure (AWS / GCP / Azure) Penetration Testing - Practitioner Reference

Companion to the network/infra, web and API guides. Covers the cloud testing flow across the control plane (provider APIs, IAM) and data plane (workloads, storage, network), per-provider specifics, and the tools that automate the boring parts. Cloud tests are authorization- and provider-terms-sensitive: agree scope, accounts, and what may not be touched (shared/managed infrastructure) before starting. Most providers now permit testing of your own resources without prior notice, but stress testing, social engineering, and anything touching the provider's control plane still need explicit permission - read the current rules of engagement for each provider.

> Fundamentals/interview framing: [../knowledge/cloud-security.md](../knowledge/cloud-security.md) | network layer: [network-infrastructure-security-testing.md](network-infrastructure-security-testing.md) | SSRF to IMDS: [web-security-testing.md](web-security-testing.md) | full tool inventory: [tools-reference.md](tools-reference.md) | methodology/CVSS/reporting: [sdlc-security-testing.md](sdlc-security-testing.md).

---

## 1. Methodology

The guiding idea: in cloud, **identity is the perimeter**. A stolen key or an over-permissioned role does what a network breach used to. Work the control plane (who can do what) before the data plane (what is exposed).

1. **Scope & access** - accounts/subscriptions/projects in scope, regions, provider rules of engagement, and the test identity. The identity defines the whole engagement: a read-only auditor key tests configuration; an assumed-breach low-privilege key tests privilege escalation and blast radius. Confirm what is managed/shared and off-limits (for example, the provider's own hypervisor, other tenants, managed-service internals).
2. **Recon & enumeration** - external (exposed assets, buckets, DNS) and authenticated (inventory every resource and the full IAM graph). You cannot assess privesc without first knowing what the identity can see and do.
3. **Config & IAM review** - benchmark the configuration against CIS / provider best practice, then map privilege-escalation paths by hand - scanners miss chained paths.
4. **Exploitation** - prove impact within scope (assume roles, read storage, reach internal services) without destructive actions. Capture evidence, do not delete or modify production data.
5. **Reporting** - map to CIS Benchmarks / provider best practices, score with CVSS (adjust for reachability), give concrete remediation, and retest after the fix.

---

## 2. Recon & enumeration

### External (unauthenticated)
- **Storage discovery:** buckets/blobs are named predictably (`company-backups`, `company-dev`). Enumerate from names, JS bundles, DNS, and certificate transparency (`crt.sh`). Test read without credentials: `aws s3 ls s3://<name> --no-sign-request`, then try `aws s3 sync` to pull contents and a `PutObject` to test world-write.
- **Exposed services & DNS:** public IPs, management planes left open, and dangling DNS records (a CNAME to a de-provisioned cloud resource) that enable **subdomain takeover**.
- **Leaked credentials:** front-end bundles, mobile apps, public repos, and CI logs for access keys, SAS tokens, and service-account JSON (`trufflehog`, `gitleaks`). A single leaked long-lived key often ends the external phase early.

### Authenticated (given a test identity)
Start by asking the provider who you are and what you can do, then inventory everything:
- **AWS:** `aws sts get-caller-identity` (who am I), `aws iam get-account-authorization-details` (full policy graph), per-service `list`/`describe`; whole-account breadth with **Prowler** / **ScoutSuite**; `enumerate-iam` to brute the effective permissions of an unknown key.
- **GCP:** `gcloud auth list`, `gcloud projects get-iam-policy <proj>`, `gcloud asset search-all-resources`; test what a token can do with `gcloud ... --impersonate-service-account`.
- **Azure:** `az account show`, `az role assignment list`, `az resource list`; **ROADtools** / **AzureHound** / **Azucar** for Entra ID (directory, app registrations, consented permissions).

---

## 3. IAM & privilege-escalation testing

This is where cloud engagements are won. Enumerate the test identity's effective permissions first, then look for a path from there to admin or to data.

- **Automate the graph:** **PMapper** (AWS) and **Pacu** `iam__privesc_scan` compute escalation paths; map GCP and Azure by hand or with purpose-built scripts.
- **Classic AWS privesc primitives** (each turns a limited permission into more):
  - `iam:CreatePolicyVersion` / `iam:SetDefaultPolicyVersion` - rewrite a policy you can edit to grant yourself `*`.
  - `iam:PassRole` + a compute service (`ec2:RunInstances`, `lambda:CreateFunction`, `glue`, `cloudformation`) - launch something running as a more privileged role and read its credentials.
  - `sts:AssumeRole` chains - hop through roles whose trust policy is too broad (wildcard or wrong account).
  - `iam:CreateAccessKey` / `iam:UpdateLoginProfile` on another user - mint credentials for a more privileged principal.
- **GCP:** service-account impersonation (`iam.serviceAccounts.getAccessToken`, `actAs`), `setIamPolicy` on a project, deploying a function/VM as a privileged service account.
- **Azure:** role-assignment write (`Microsoft.Authorization/roleAssignments/write`) = grant yourself `Owner`; `Owner`/`Contributor` on a scope; abusing managed identities on a VM you control; Entra application/consent abuse.
- **Trust misconfig:** cross-account/cross-project roles with `*` principals, confused-deputy conditions missing (`sts:ExternalId`), and keys that never rotate.

---

## 4. Data-plane testing

- **Storage:** world- and authenticated-user read **and write**, server-side encryption, object versioning, and public snapshots/AMIs/disk images (a public EBS snapshot or RDS snapshot leaks whole databases).
- **Compute:** instance metadata reachability - IMDSv1 is unauthenticated and trivially reachable through SSRF; IMDSv2 requires a PUT-obtained session token and a low hop limit. Also check user-data for secrets, over-scoped instance roles, and SSH/RDP exposed to the internet.
- **Network:** security groups / firewall rules allowing `0.0.0.0/0` on sensitive ports, public databases and management planes, missing segmentation, and over-trusting VPC peering.
- **Serverless:** execution-role scope (functions over-privileged "to make it work"), secrets in environment variables, and event-source injection (malicious input in an SQS/SNS/S3 event the function trusts).
- **Containers / Kubernetes:** anonymous API server access, privileged or `hostPath` pods, RBAC bindings to `system:anonymous` or `system:authenticated`, and pods able to reach the node's metadata service to steal the node role.

---

## 5. Provider automated benchmarks

| Tool | Scope | Use |
| --- | --- | --- |
| Prowler | AWS (GCP/Azure growing) | CIS benchmark + hundreds of checks, CLI |
| ScoutSuite | AWS/GCP/Azure/others | multi-cloud config audit, HTML report |
| Pacu | AWS | exploitation framework (modules for privesc, enum, backdoor) |
| PMapper | AWS | IAM privilege-escalation graph |
| CloudSploit | multi | config scanning |
| ROADtools / AzureHound | Azure / Entra ID | directory enumeration + attack paths |

Run a benchmark scan early for breadth, then validate findings manually - scanners both over-report (flagging accepted risk) and under-report (missing chained privesc). A clean ScoutSuite report is not a clean account.

---

## 6. Practical command chains

- **Bucket loot:** enumerate names -> `aws s3 ls s3://b --no-sign-request` -> `aws s3 sync s3://b . --no-sign-request` -> triage for secrets/PII.
- **Key triage:** `gitleaks detect` on a repo -> validate a found key with `aws sts get-caller-identity` -> `prowler aws` scoped to that account to map what it exposes.
- **IMDS via SSRF:** app SSRF -> `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` -> export the returned temp creds and use the CLI (in scope only).
- **IAM privesc:** `aws iam get-account-authorization-details` -> load into PMapper -> follow the graph to assume the reachable admin role.

---

## 7. Tools & checklist

**Multi-cloud:** ScoutSuite, CloudSploit, Steampipe. **AWS:** Prowler, Pacu, PMapper, enumerate-iam, CloudMapper. **GCP:** ScoutSuite, GCP IAM privesc scripts. **Azure/Entra:** ROADtools, AzureHound, Azucar. **Secrets:** trufflehog, gitleaks. (Full inventory in [tools-reference.md](tools-reference.md).)

**Engagement checklist:**
- [ ] authorization + provider terms + scope agreed
- [ ] test-identity permission enumeration done
- [ ] external exposure mapped (buckets, IPs, DNS, leaked keys)
- [ ] IAM reviewed + privesc paths traced
- [ ] storage public/writable + encryption checked
- [ ] metadata IMDSv2 enforced + SSRF reachability tested
- [ ] network exposure reviewed (SG/firewall, public DB/mgmt)
- [ ] serverless / container / k8s checks done
- [ ] logging / monitoring / encryption verified
- [ ] benchmark (CIS) mapping + CVSS + remediation + retest

## Quick mental model
Identity is the perimeter. Enumerate what your key can do, find who it can become, and prove the shortest path to data or admin - without breaking shared infrastructure.
