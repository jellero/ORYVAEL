# Contributing

ORYVAEL treats architecture, policy and provenance as first-class code.

Every meaningful change should answer:
1. What requirement or defect motivates it?
2. Which trust boundary changes?
3. Which capabilities are added or expanded?
4. Which dependencies change?
5. Which invariants may be affected?
6. How is behavior verified?
7. How can it be rolled back?

## Engineering rules

- prefer deletion and simplification over permanent complexity;
- avoid hidden network access;
- avoid runtime dependency discovery in Trusted Core;
- pin release toolchains;
- keep the TCB small;
- add tests before expanding privileges;
- never weaken a failing security check merely to make CI pass;
- keep AI/model SDKs outside Trusted Core;
- never silently downgrade a mandatory security primitive.

See docs/governance/change-classes.md for C0-C4 rules.
