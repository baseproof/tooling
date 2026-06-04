# `services/auditor/deploy`

Deployment manifests for the **auditor** service only (Helm chart / k8s).

The auditor is deployed **per network**: the same image, configured by env +
mounted bootstrap, runs one instance per network it audits. The auditor service
itself is implemented (`../cmd/auditor`, see [../README.md](../README.md)); the
Helm chart / k8s manifests in this directory are a placeholder and land
alongside the first real release.
