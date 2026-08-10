# Floci-backed live E2E emulation

This repository uses [Floci](https://github.com/floci-io/floci) to exercise the
live E2E AWS adapter and a mocked runner orchestration path without touching a
real AWS account.

Floci is **not** a substitute for an approved live AWS deployment. Real
`preflight` / `run` / `cleanup` against AWS remain local-only and require the
guards in [LIVE-E2E.md](LIVE-E2E.md).

## What CI covers

The `Floci Live E2E Emulation` job in `.github/workflows/ci.yml`:

1. Starts `floci/floci:1.6.0` through Testcontainers
2. Seeds STS identity, a dedicated Route 53 zone, CDK bootstrap stack, and
   bootstrap IAM roles
3. Runs `LiveE2EAws.preflight` against the emulator (service-quotas, IAM policy
   simulation, and emulator-unsupported read APIs such as EFS are Floci-emulated
   shims)
4. Verifies owned-stack cleanup refuses foreign ownership markers
5. Runs a mocked runner path (`preflight` → approved `run` → cleanup) with the
   OpenEMR live E2E CDK deploy/validate stubbed and CloudFormation state held in
   Floci
6. Runs a real pinned-CDK lifecycle against Floci for the minimal smoke stack in
   `tools/floci_cdk/`: `cdk bootstrap` → `cdk deploy` → `cdk destroy`

GitHub Actions never invokes `python -m tools.live_e2e preflight|run|cleanup`.

## Local commands

```bash
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
npm ci
pytest tests/tools/test_floci_emulator.py -q
pytest tests/tools/test_floci_e2e.py tests/tools/test_floci_cdk_deploy.py -m floci -q
```

Optional compose helper (usually unnecessary; tests start Floci themselves):

```bash
docker compose -f compose/docker-compose.floci.yml up
export OPENEMR_FLOCI_E2E=1
export OPENEMR_AWS_ENDPOINT_URL=http://127.0.0.1:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
```

## Safety

- `OPENEMR_FLOCI_E2E=1` is required before CI signals are ignored
- The endpoint must be local (`localhost`, `127.0.0.1`, Docker bridge, `floci`)
- Real AWS hostnames are rejected
- Emulated mode never contacts `service-quotas`; write-permission simulation is
  replaced by IAM role existence checks after successful `AssumeRole`
- Emulator `UnknownOperationException` responses on read probes (for example EFS)
  are recorded as Floci-emulated passes instead of failing preflight

## Limits

The Floci CDK smoke stack is not the OpenEMR application stack. Aurora
Serverless v2, ElastiCache Serverless, WAF associations, custom resources, and
OpenEMR container asset publishing remain covered by synthesis tests and an
explicitly approved live AWS run.
