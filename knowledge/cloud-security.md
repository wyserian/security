# Cloud Infrastructure Security - Reference & Interview Prep

Cloud testing targets the control plane (the provider APIs and IAM that define
what exists and who can touch it) as much as the workloads themselves. Most real
cloud breaches are misconfiguration and identity problems, not kernel exploits:
a public bucket, an over-permissive role, a leaked access key, a metadata SSRF.
AWS, GCP and Azure differ in names but share the model below. Findings follow
the usual **What -> Why -> How -> Impact -> Mitigations** shape used across
these notes.

Fundamentals (shared responsibility, SG vs NACL, IAM least-privilege) also
appear in [network-and-fundamentals.md](network-and-fundamentals.md); SSRF to
instance metadata is detailed in [web-security.md](web-security.md).

---

## 1. Core concepts

### Shared responsibility
The provider secures "of the cloud" (hardware, hypervisor, managed-service
internals); the customer secures "in the cloud" (IAM, data, config, patching of
anything they run). Almost every finding you report is on the customer side.

### The three providers at a glance

| Concept | AWS | GCP | Azure |
| --- | --- | --- | --- |
| Account boundary | Account / Organization | Project / Folder / Org | Subscription / Tenant |
| Identity | IAM users, roles, policies | IAM members + roles, service accounts | Entra ID (AAD), RBAC, managed identities |
| Object storage | S3 | Cloud Storage (GCS) | Blob Storage |
| Compute | EC2 | Compute Engine | Virtual Machines |
| Secrets | Secrets Manager, SSM Param | Secret Manager | Key Vault |
| Metadata endpoint | 169.254.169.254 (IMDSv1/v2) | metadata.google.internal | 169.254.169.254 (IMDS) |
| Serverless | Lambda | Cloud Functions | Functions |
| Audit log | CloudTrail | Cloud Audit Logs | Activity Log |

### Identity is the perimeter
There is no network edge to hide behind: a valid key or token from anywhere is
access. Roles assumed by workloads, federated/SSO identities, and long-lived
user keys are all attack surface. "Who can become whom" (privilege-escalation
paths through `iam:PassRole`, `sts:AssumeRole`, token impersonation) matters
more than any single permission.

---

## 2. Common cloud findings

### Public / misconfigured object storage
**What.** Buckets or blobs readable (or writable) by anyone, or by any
authenticated account.
**Why.** ACLs/policies set to `AllUsers`/`AuthenticatedUsers`, "block public
access" disabled, or a bucket policy with `"Principal": "*"`.
**How.** `aws s3 ls s3://<bucket> --no-sign-request`, enumerate names from
JS/DNS/`crt.sh`, check website endpoints, test write with a harmless file.
**Impact.** Data leak (PII, backups, source), or write -> content/supply-chain
tampering and bucket defacement.
**Mitigations.** Block public access at account level, least-privilege bucket
policies, deny `*` principals, enable access logging, encrypt at rest.

### Over-permissive IAM and privilege escalation
**What.** Identities with far more than they need (`*:*`, wildcard resources),
or escalation paths to admin.
**Why.** Convenience policies, unused permissions never pruned, `iam:PassRole`
plus a service that runs with a role.
**How.** Enumerate your own permissions (`aws iam get-account-authorization-details`,
GCP `gcloud projects get-iam-policy`), run **PMapper**/**Pacu** or GCP IAM
privesc checks; look for `iam:CreatePolicyVersion`, `iam:PassRole` +
`lambda:CreateFunction`, `sts:AssumeRole` chains.
**Impact.** Lateral movement and full account takeover from a low-priv identity.
**Mitigations.** Least privilege, no inline wildcards, permission boundaries /
SCPs, scoped `PassRole`, regular access reviews, Access Analyzer.

### Leaked / long-lived credentials
**What.** Access keys, service-account JSON, SAS tokens in code, CI logs, images
or client bundles.
**Why.** Hardcoding, committed `.env`, keys that never rotate.
**How.** `trufflehog`/`gitleaks` on repos and history, inspect AMIs/containers,
search front-end JS, check for keys in instance user-data.
**Impact.** Direct authenticated access, often long-lived.
**Mitigations.** Workload identity / roles instead of static keys, short-lived
tokens, secret scanning in CI, rotation, deny-list committed secrets.

### Instance metadata SSRF (IMDS)
**What.** SSRF in a workload reaches the metadata endpoint and steals the
attached role's temporary credentials.
**Why.** A fetch-a-URL feature + IMDSv1 (no session token required).
**How.** Point SSRF at `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
(AWS), `metadata.google.internal` with `Metadata-Flavor: Google` (GCP).
**Impact.** Full use of the workload's role from outside.
**Mitigations.** Enforce IMDSv2 (hop limit, token required), least-priv instance
roles, egress filtering, block link-local from app layer. See SSRF in
[web-security.md](web-security.md#server-side-request-forgery-ssrf).

### Exposed management / data services
**What.** Databases, dashboards, queues, Kubernetes API, RDP/SSH open to the
internet or to `0.0.0.0/0`.
**Why.** Over-broad security groups / firewall rules, default-open managed
services, no network segmentation.
**How.** Review SG/firewall rules, scan public IP ranges, check `kubectl` on
exposed API servers, test default creds.
**Impact.** Direct data access or compute compromise.
**Mitigations.** Private subnets, bastion/SSM, least-open rules, private
endpoints for managed services, no public DB.

### Logging, monitoring and encryption gaps
**What.** CloudTrail/Audit logs off or not centralized, no alerting, unencrypted
volumes/snapshots, public snapshots/AMIs.
**Impact.** Attacks go unseen; data recoverable from shared snapshots.
**Mitigations.** Org-wide audit logging to a locked account, GuardDuty/Security
Command Center, default encryption, deny public sharing of snapshots.

---

## 3. Service-specific gotchas

- **Serverless (Lambda/Functions):** over-scoped execution role, secrets in env
  vars, event-data injection, and the function's role reachable via SSRF/RCE.
- **Containers / Kubernetes:** anonymous API access, privileged pods,
  hostPath mounts, secrets in env, cluster role bindings to `system:anonymous`,
  node IMDS reachable from pods (block with a hop limit / network policy).
- **SaaS-ish managed services:** resource-based policies that trust the whole
  org, cross-account `*` trust, public snapshots/images.

---

## 4. Interview-style answers

- **"How do cloud pentests differ from on-prem?"** The perimeter is identity and
  the provider API, not the network. You spend most time on IAM, config and the
  control plane; scope and provider authorization (e.g. not DoSing shared
  infrastructure) are explicit.
- **"Most common root cause of cloud breaches?"** Misconfiguration and identity:
  public storage, leaked keys, over-permissive roles, metadata SSRF.
- **"IMDSv1 vs IMDSv2?"** v2 requires a PUT-issued session token and supports a
  hop limit, which defeats most SSRF credential theft; enforce v2.
- **"Explain the shared responsibility model."** The provider secures the cloud
  *of* the infrastructure (hardware, hypervisor, managed-service internals); the
  customer secures what they put *in* it (IAM, data, configuration, OS/app on
  IaaS). The split shifts by service model - more is yours on IaaS, less on SaaS -
  and nearly every cloud breach falls on the customer side (misconfig/identity).
- **"Security Group vs NACL (AWS)?"** A Security Group is a *stateful* firewall at
  the instance/ENI level (return traffic auto-allowed, allow-rules only); a
  Network ACL is *stateless* at the subnet level (you must allow both directions,
  supports explicit deny). SGs are the primary control; NACLs are coarse
  subnet-wide guardrails.
- **"How does SSRF become cloud credential theft?"** An app that fetches a
  user-supplied URL can be pointed at the metadata service
  (`169.254.169.254/.../iam/security-credentials/<role>`), which hands back the
  instance role's temporary keys - instant access as that role. IMDSv2 + fixing
  the SSRF is the fix.
- **"What is a confused-deputy / cross-account trust issue?"** A role whose trust
  policy allows another account (or `*`) to assume it without an `ExternalId`
  condition lets a third party act as your role. Scope trust tightly and require
  an `ExternalId` for third-party access.

---

## 5. Quick checklist

- [ ] Authorization + provider terms (no out-of-scope / shared-tenant impact)
- [ ] IAM review: wildcard policies, privesc paths, PassRole, unused creds
- [ ] Storage: public/writable buckets/blobs, encryption, logging
- [ ] Credentials: leaked keys in code/CI/images, long-lived vs workload identity
- [ ] Network: SG/firewall exposure, public DB/mgmt, segmentation
- [ ] Metadata: IMDSv2 enforced, SSRF reachability
- [ ] Serverless/containers/k8s specific checks
- [ ] Logging/monitoring/alerting + default encryption
