# Observability Architecture

## Scope

ORYVAEL observes:
- kernel/system health;
- service behavior;
- application behavior where policy allows;
- AI agent actions;
- build and release pipelines;
- security enforcement.

## Telemetry flow

~~~
kernel / services / apps / AI agents
                |
        telemetry collectors
          /      |      \
     metrics    logs    traces
          \      |      /
          observability store
              /       \
         human UI     AI Ops
~~~

Prometheus/OpenTelemetry-compatible data is preferred in the Linux-first phase. Grafana is a suitable visualization layer but is not part of the Root of Trust.

## Independent observation

Critical services should be observed from a supervisor/lower layer where practical. A service's self-reported health is useful but not sufficient.

## Audit versus telemetry

Telemetry optimizes diagnosis and trend analysis.

Audit optimizes attribution and tamper evidence.

They share operation IDs where useful but have different retention and integrity semantics.

## Privacy rules

- never emit secrets by design;
- minimize sensitive content;
- avoid high-cardinality personal identifiers;
- do not log raw prompts by default;
- model input/output capture requires explicit policy;
- classify data before remote export.

## Reference dashboards

**System:** boot, crashes, CPU/RAM/I/O, thermal/battery, updates.

**AI Engineering:** generated changes, verifier results, rollback rate, dependency/TCB growth.

**Security:** denied capabilities, sandbox violations, policy changes, signature failures, unexpected network attempts.

**Release:** rollout ring, canary health, regression thresholds, rollback.
