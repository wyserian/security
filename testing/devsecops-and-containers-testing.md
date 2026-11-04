# DevSecOps, CI/CD & Container / Kubernetes Security - Practitioner Reference

Companion to the SDLC, cloud and source-code-audit guides. Covers testing the
delivery pipeline and the platform it ships to: CI/CD pipeline security, the
security-automation tooling wired into it, and container + Kubernetes
configuration. Scope carefully - the pipeline and cluster often hold
production-level access, and some checks (runtime scanning, cluster attacks) need
explicit authorization.

> Concepts/interview framing: [../knowledge/devsecops-and-containers.md](../knowledge/devsecops-and-containers.md) | lifecycle hub: [sdlc-security-testing.md](sdlc-security-testing.md) | SAST/code review: [source-code-audit-testing.md](source-code-audit-testing.md) | cloud platform: [cloud-security-testing.md](cloud-security-testing.md) | full tool inventory: [tools-reference.md](tools-reference.md).

---

## 1. Methodology

1. **Scope & access** - which repos, pipelines, registries, and clusters; read
   access vs assumed-breach; what is managed/shared and off-limits.
2. **Pipeline review** - CI/CD config, credentials, flow control, secrets,
   artifact integrity.
3. **Automation audit** - is the scan stack present, gating, and tuned?
4. **Container testing** - image and runtime configuration.
5. **Kubernetes testing** - cluster config, RBAC, workloads, network, secrets.
6. **Report** - map to OWASP CI/CD Top 10 and CIS benchmarks, CVSS, fixes, retest.

---

## 2. CI/CD pipeline review (OWASP CI/CD Top 10)

The pipeline is a high-value target: it holds deploy credentials, runs untrusted code (every PR), and pushes straight to production. Work each OWASP CI/CD risk:

- **Flow control / Poisoned Pipeline Execution (PPE):** can a pull request change what CI runs? If the pipeline definition lives in the repo and a build triggers on PRs from forks, an attacker edits the workflow (or a build script / Makefile / test it calls) to run their code on the runner - with the runner's credentials. *Direct PPE* = edit the CI config; *Indirect PPE* = edit a file the config executes (e.g. a `prebuild` npm script). Fix: require review on pipeline-definition changes, do not run privileged steps on fork PRs, and separate build from deploy.
- **Insufficient flow control / dependency chain:** **dependency confusion** - if the build resolves an internal package name (`@acme/utils`) and an attacker publishes that name to the public registry with a higher version, the public one may win. Check registry precedence, scoped-package config, and version pinning (lockfiles committed). Typosquatting and unpinned `latest` are the same class.
- **IAM:** pipeline credential scope and lifetime. Prefer short-lived OIDC federation over long-lived static cloud keys stored as secrets; scope deploy credentials to exactly what the job needs; control who can trigger a deploy.
- **Secrets:** secrets in pipeline config, environment variables, or build logs (echoed by a debug step); confirm masking works and a real secret manager is used, not repo variables. Test whether a malicious PR can exfiltrate a secret by printing it.
- **Runners:** shared vs ephemeral/isolated runners; a self-hosted runner reused across trust levels lets one job's malware persist for the next. Prefer ephemeral runners per job.
- **Artifact integrity:** are images/artifacts signed (cosign/Sigstore) with an SBOM (Syft) and build provenance (SLSA)? Unsigned artifacts allow a tampered image to be deployed as trusted.
- **Logging:** are pipeline actions and approvals audited, so a malicious change is attributable?

## 3. Security-automation audit (is the stack real?)
| Stage | Tool examples |
| --- | --- |
| SAST | Semgrep, CodeQL, SonarQube |
| SCA | Snyk, OWASP Dependency-Check, Trivy (fs) |
| Secrets | gitleaks, trufflehog |
| IaC | Checkov, tfsec, KICS, Terrascan |
| Image | Trivy, Grype, Dockle |
| Policy as code | OPA/Conftest, Kyverno |
| DAST | OWASP ZAP, Nuclei |
Confirm they run automatically, gate on severity, and have a triage path - a scan
that never fails the build and nobody reads is theatre.

## 4. Container image & runtime testing
### Image
```bash
trivy image <image:tag>        # CVEs + secrets + misconfig
grype <image:tag>              # CVE scan
dockle <image:tag>             # Dockerfile/CIS best practices
docker history --no-trunc <img># leaked build steps / secrets
```
Review the Dockerfile: non-root `USER`, pinned minimal base, no secrets/ARGs
leaking, no `latest`, no shell/package manager left in the final stage.

### Runtime
Check for `--privileged`, host namespace sharing, mounted `docker.sock` or
`hostPath`, missing capability drops, writable root FS, missing seccomp/AppArmor,
and no resource limits. Any of these weaken or remove the container boundary.

## 5. Kubernetes testing
```bash
kube-bench                     # CIS Kubernetes Benchmark
kube-hunter                    # remote/in-cluster attack surface
kubeaudit all                  # common workload misconfigs
kubectl auth can-i --list      # current token's permissions
kubectl get pods -A -o jsonpath # find privileged/hostPath pods
```
- **RBAC** - bindings to `cluster-admin`/`system:anonymous`, risky verbs
  (`create pods`, `get secrets`, `escalate`, `bind`, `impersonate`).
- **API server** - anonymous auth, public exposure, anonymous `kubectl`.
- **Workloads** - privileged, hostPath, hostNetwork/PID, root, auto-mounted
  service-account tokens.
- **Network** - absence of NetworkPolicies (flat east-west).
- **Secrets** - unencrypted at rest, in env/manifests.
- **Metadata** - can a pod reach the node's cloud IMDS and steal node creds?
- **Attack chain** - low-priv pod -> token or node access -> cluster-admin:
  prove the path in scope only.

## 6. Tools & checklist
**Pipeline/supply-chain:** cosign/Sigstore, Syft (SBOM), SLSA verifiers.
**SAST/SCA/secrets:** Semgrep, CodeQL, Snyk, gitleaks, trufflehog. **IaC:**
Checkov, tfsec, KICS, Terrascan. **Image:** Trivy, Grype, Dockle. **K8s:**
kube-bench, kube-hunter, kubeaudit, Trivy-operator, Polaris, OPA/Kyverno.
(Full inventory in [tools-reference.md](tools-reference.md).)

**Checklist:**
- [ ] authorization + scope (pipeline/registry/cluster)
- [ ] pipeline flow control / anti-PPE + change review
- [ ] pipeline IAM (short-lived, scoped)
- [ ] secrets management + scanning
- [ ] dependency chain (SCA, pinning, registry)
- [ ] artifact signing + SBOM + provenance
- [ ] scan stack present + gating
- [ ] image: non-root, minimal, no secrets, scanned
- [ ] runtime: no privileged/host mounts, caps dropped, read-only FS
- [ ] K8s: RBAC least-priv, network policies, pod security admission, API not public
- [ ] K8s secrets encrypted + node metadata blocked
- [ ] findings mapped (OWASP CI/CD / CIS) + CVSS + fix + retest.

## Quick mental model
The pipeline and cluster have production-level power, so test them like
production. Secure how code ships (pipeline + supply chain), then how it runs
(container + Kubernetes isolation) - and check the automation actually gates.
