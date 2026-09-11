# ERSEC 29.1.0 Universal Assessment Workspace

The Assessment Workspace is the first P0 capability of the next ERSEC roadmap. It is a local-first correlation layer for authorized assessments.

## Design guarantees

- No network access is performed while importing artifacts.
- Imported source bytes receive SHA-256 provenance digests.
- Canonical assets, services and API operations receive stable content-derived IDs.
- Reordered query parameters and repeated observations converge on one operation identity.
- Original source references are retained on normalized objects.
- Export digests exclude only wall-clock import timestamps; semantic content remains deterministic.
- Credential values are not interpreted as credentials by the workspace importer; operators should use redacted exports and references.

## Supported initial adapters

Nmap XML, Masscan-style host/port lines, Subfinder/domain lists, httpx JSON/JSONL, HAR, OpenAPI/Swagger, Postman collections, AsyncAPI, supplied GraphQL/gRPC operation documents, SARIF, and Nuclei JSONL.

The adapters normalize evidence; they do not execute imported commands or contact targets.

## CLI

```bash
python3 ersec.py --workspace-init ./case-acme --workspace-target https://staging.example.test
python3 ersec.py --workspace-ingest nmap.xml subfinder.txt httpx.json traffic.har api.json --workspace-directory ./case-acme
python3 ersec.py --workspace-export ./case-acme/workspace-export.json --workspace-directory ./case-acme
```

For direct module use:

```bash
python3 ersec_workspace.py init ./case-acme
python3 ersec_workspace.py ingest ./case-acme nmap.xml api.json
python3 ersec_workspace.py export ./case-acme --output workspace.json
```

## Security boundary

The workspace is intentionally an evidence/correlation component. Active assessment remains governed by ERSEC's authorization manifest, scope enforcement, risk budget, and proof/assurance engines.
