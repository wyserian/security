# DevSecOps, CI/CD & Container / Kubernetes Security - Reference & Interview Prep

DevSecOps builds security into the DevOps pipeline instead of bolting it on at
the end: shift-left, automate the checks, and make security everyone's job. In
practice that means securing three things together - the **CI/CD pipeline** that
builds and ships code, the **security automation** wired into that pipeline
(SAST/DAST/SCA/IaC/image scanning as gates), and the **container / Kubernetes
platform** modern apps run on. Findings follow the usual
**What -> Why -> How -> Impact -> Mitigations** shape.

Lifecycle and SAST/DAST concepts live in
[methodology-and-sdlc.md](methodology-and-sdlc.md); SAST detail in
[source-code-audit.md](source-code-audit.md); the cloud that hosts clusters in
[cloud-security.md](cloud-security.md).

---

## 1. DevSecOps core concepts
- **Shift-left** - find and fix issues early (design/code/build), where they are
  cheapest, instead of in production.
- **Automate the gates** - security checks run in the pipeline, not as a manual
  step, and can fail the build on policy breach.
- **Everyone owns security** - devs, ops and security share responsibility
  (CALMS: Culture, Automation, Lean, Measurement, Sharing).
- **Policy as code** - security rules are versioned and enforced automatically
  (OPA/Rego, Kyverno, admission controllers).
- **The scan stack** - SAST (code), SCA (dependencies), secret scanning, IaC
  scanning, container image scanning, DAST (running app), each at the right
  pipeline stage.

## 2. CI/CD pipeline security (OWASP Top 10 CI/CD risks)
The pipeline has admin-level reach (it builds, signs and deploys), so it is a
high-value target.

- **Insufficient flow control (PPE - Poisoned Pipeline Execution)** - an attacker
  who can modify pipeline config or a build script runs code in the CI context.
  Mitigate: review-gate pipeline changes, separate build from deploy, least
  privilege for jobs.
- **Inadequate identity & access management** - over-privileged pipeline
  credentials, long-lived tokens. Mitigate: short-lived OIDC tokens, scoped
  service accounts.
- **Dependency chain abuse** - dependency confusion, typosquatting, malicious
  packages. Mitigate: pin versions, private registries, verify checksums, SCA.
- **Secrets exposure** - credentials in pipeline config, logs or env. Mitigate:
  a secrets manager, masked logs, secret scanning.
- **Insecure system/runner config** - compromised or shared build runners.
  Mitigate: ephemeral isolated runners, no reuse across trust levels.
- **Insufficient artifact integrity** - unsigned artifacts/images. Mitigate:
  sign (Sigstore/cosign), generate an SBOM, attest provenance (SLSA).
- **Ungoverned third-party plugins** and **insufficient logging** round out the
  list.

## 3. Security automation - what runs where
| Stage | Checks |
| --- | --- |
| Pre-commit / local | secret scan, linting |
| PR / build | SAST, SCA, secret scan, IaC scan, unit tests |
| Artifact | container image scan, SBOM, sign |
| Pre-deploy | policy-as-code gate, config/IaC validation |
| Post-deploy / runtime | DAST, runtime scanning, monitoring |
Gates should fail fast on high-severity, with a triage path for false positives
so security does not block delivery unnecessarily.

## 4. Container security
### Image
- Minimal, pinned base images; no secrets baked in; run as non-root; drop
  unnecessary packages. Scan with Trivy/Grype for known CVEs.
- Common findings: `latest` tags, root user, hardcoded secrets, vulnerable base,
  unnecessary tools (shell, package manager) in the final image.

### Runtime
- Drop Linux capabilities, read-only root filesystem, no `--privileged`, no host
  namespace sharing, resource limits, seccomp/AppArmor profiles.
- Common findings: privileged containers, host mounts (`/var/run/docker.sock`,
  `hostPath`), containers that can reach the node or other tenants.

## 5. Kubernetes security
- **RBAC** - least privilege; no bindings to `cluster-admin` or
  `system:anonymous`; audit `can-i` for risky verbs.
- **API server exposure** - anonymous auth disabled, API not public, etcd
  encrypted and access-controlled.
- **Pod security** - Pod Security Standards / admission control (OPA Gatekeeper,
  Kyverno) to block privileged/hostPath/root pods.
- **Network policies** - default-deny east-west traffic; without them a pod
  talks to everything.
- **Secrets** - Kubernetes Secrets are base64, not encrypted by default; enable
  encryption at rest or use an external vault; do not put secrets in env/manifests.
- **Node/metadata** - block pods from reaching the node's cloud metadata (IMDS)
  to stop credential theft (ties to [cloud-security.md](cloud-security.md)).
- **Attack path** - a privileged/hostPath pod or a token-mounted service account
  -> node -> cluster-admin is the classic escalation.

## 6. Interview-style answers
- **"What is DevSecOps?"** Integrating security into the DevOps pipeline -
  shift-left, automate security checks as gates, and share ownership across dev,
  ops and security, rather than a separate late-stage audit.
- **"How do you secure a CI/CD pipeline?"** Treat it as production: least-privilege
  short-lived credentials, review-gate pipeline changes (stop PPE), isolated
  ephemeral runners, secret management, signed artifacts + SBOM, and the scan
  stack as gates.
- **"Why are containers not a security boundary by default?"** They share the
  host kernel; a privileged container, host mount, or kernel exploit escapes to
  the node. Isolation needs dropped capabilities, non-root, seccomp, and policy.
- **"Biggest Kubernetes misconfigurations?"** Over-permissive RBAC, no network
  policies, privileged/hostPath pods, exposed API, and unencrypted secrets.
- **"Container vs VM isolation?"** A VM virtualises hardware and runs its own
  kernel (strong isolation, heavier); a container shares the host kernel and
  isolates with namespaces + cgroups (lightweight, weaker boundary). A kernel
  bug or a privileged/host-mounted container can escape to the host - a VM
  escape is far rarer.
- **"What is a container escape?"** Breaking out of the container to the host:
  via `--privileged`, a mounted `docker.sock` (control the daemon), a `hostPath`
  mount of the root FS, excessive capabilities (`CAP_SYS_ADMIN`), or a kernel
  exploit. Once on the node, a token-mounted service account often reaches
  cluster-admin.
- **"What are SBOM, SLSA and Sigstore?"** An SBOM (Syft) is a machine-readable
  inventory of everything in an artifact (for CVE response); SLSA is a framework
  of provenance/integrity levels for the build supply chain; Sigstore/cosign
  signs artifacts and images so a consumer can verify they are untampered and
  from the expected build.
- **"Dependency confusion - what and fix?"** If a build resolves an internal
  package name and an attacker publishes that same name publicly with a higher
  version, the public (malicious) one can win. Fix: scoped/namespaced packages,
  pin versions with committed lockfiles, and configure registry precedence to
  prefer the private source.

## 7. Quick checklist
- [ ] Pipeline: least-priv short-lived creds, change review (anti-PPE), isolated runners
- [ ] Secrets: manager + scanning, none in config/logs/images
- [ ] Dependencies: SCA, pinned versions, private registry
- [ ] Artifacts: signed + SBOM + provenance (SLSA)
- [ ] Scan stack wired as gates (SAST/SCA/secret/IaC/image/DAST)
- [ ] Images: minimal, non-root, no secrets, scanned
- [ ] Containers: no privileged, no host mounts, caps dropped, read-only FS
- [ ] K8s: least-priv RBAC, network policies, pod security admission, API not public
- [ ] K8s secrets encrypted; pods blocked from node metadata
