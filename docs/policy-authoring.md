# Writing policy

The rules file is the product surface. This document is what an operator — or a
developer using a programmatic policy API built on top of this — needs to know
to write a rule that does what they meant.

## The shape of a decision

Every request produces exactly one decision, and every decision names the rule
that produced it. There is no rule chaining, no fallthrough accumulation and no
"apply all matching rules" — `evaluate()` scans rules in priority order and
stops at the first match. That is a deliberate constraint: it means a decision
can be explained by pointing at one line of one file, which is what an audit,
a billing dispute and a 3 a.m. page all need.

When no rule matches, `default_action` applies. It defaults to `DENY`, and
should stay that way: a policy engine that fails open is a billing incident,
and for a barred device it is a compliance one.

## File structure

```yaml
version: 1                  # informational; the live version is assigned at load
dnns: [internet, ims, ...]  # the DNN table — wire requests carry the INDEX
redirects:                  # named redirect targets
  portal: "https://..."
plans:                      # defaults a rule can inherit
  - name: dev-basic
    ...
roaming_partners: [310-260, ...]
imei_blocklist: [...]       # inline list, or a path to a file of IMEIs
default_action: {...}
rules: [...]
```

### `dnns` — the one section you cannot reorder

The wire format carries `dnn_id`, an index into this list, because a string
comparison has no business on the decision path. **Appending is safe. Reordering
or removing an entry renumbers every deployed client's enum**, and the failure
is silent: requests keep arriving and keep getting plausible decisions for the
wrong APN. Treat this list as append-only.

### `plans`

A plan supplies the values a rule may inherit rather than restate:

```yaml
- name: dev-basic
  qos_5qi: 9            # 1..255; standardized values are checked, others warn
  arp: 8                # 1..15, 1 is highest priority
  ambr_ul: 10Mbps       # bare numbers are kbps
  ambr_dl: 50Mbps
  quota: 20GB           # GB is 10^9; GiB is 2^30. They are not the same.
  quota_validity: 30d
  rating_group: 100
  tethering: true
  roaming: true
```

Plans hold **defaults, not restrictions.** Everything that can deny a request is
a rule, so every denial has a rule id somebody can point at. A plan that simply
cannot use the `ims` DNN gets a rule saying so, not a field.

Plan identity is positional: subscriber records store the plan's index. A reload
that renames or reorders a plan is **refused** — it needs a restart, because
otherwise every affected subscriber silently moves onto a different tariff.

### `rules`

```yaml
- id: 61                  # non-zero, unique, stable — it appears in decisions
  name: post-quota-throttle  # for humans; not used at runtime
  priority: 61            # ascending; ties keep file order
  plans: dev-basic        # optional; omit to apply to every plan
  when:
    quota_exhausted: true
  action:
    verdict: ALLOW
    reason: QUOTA_EXHAUSTED_THROTTLED
    inherit: [qos, rating_group]
    ambr_ul: 1Mbps
    ambr_dl: 1Mbps
    quota: 1GB
    quota_validity: 24h
    flags: [throttled]
```

`id` is a contract. It goes out on the wire in every decision the rule produces
and ends up in CDRs and dashboards. Renumbering a rule breaks anything that was
counting it. Use a numbering scheme with gaps — this repo's config uses bands
(1–19 global gates, 20–39 roaming, 40–59 entitlement, 60–79 quota, 100+ plan
defaults) so a new rule rarely needs to displace an existing one.

## Conditions

Every condition below compiles to bits in a 64-bit feature word. A rule's whole
match is one `(mask, value)` pair, tested with two ANDs and a compare.

### Boolean

| Condition | True when |
|---|---|
| `roaming` | the serving PLMN differs from the subscriber's home PLMN |
| `home_plmn` | the serving PLMN is the home PLMN |
| `roaming_partner` | the serving PLMN is in `roaming_partners` |
| `roaming_allowed` | the subscriber's own subscription permits roaming |
| `imei_known` | the request carried a non-zero IMEI |
| `imei_blocked` | that IMEI is in the blocklist |
| `tethering_detected` | the serving node's traffic detection flagged tethering |
| `tethering_allowed` | the plan or the subscriber permits it |
| `emergency` | the request is flagged as an emergency session |
| `quota_exhausted` | usage has reached the plan's quota |
| `period_expired` | the metering period's reset time has passed |
| `requested_gbr` | the requested 5QI is a GBR class |

Each takes `true` or `false`. Omitting a condition means the rule does not care.

### One-hot sets

`status`, `rat` and `dnn` select from a fixed set:

```yaml
when:
  status: ACTIVE          # ACTIVE | SUSPENDED | BARRED | UNKNOWN
  rat: NR                 # LTE | NR | WLAN  (4G/5G/WiFi also accepted)
  dnn: internet
```

A **list** means "any of":

```yaml
when:
  dnn: [ims, mms, tethering]
```

This is where the implementation shows through: `(mask, value)` cannot express
OR, so a list of *n* alternatives compiles to *n* rules sharing the id, priority
and action. Combinations multiply — `dnn` of 2 and `rat` of 3 is six compiled
rules — and the compiler refuses anything over 64 per source rule and tells you
to split it. `not_dnn` and `not_rat` mean "none of these", which *is* one pair,
so negation never expands.

### Thresholds and time

```yaml
when:
  usage_above: 80%                                  # or 0.8, or 80
  time_between: { start: "02:00", end: "06:00" }    # local time, wraps midnight
```

`usage_below` and `not_time_between` are the negations.

These are not evaluated per rule. The compiler collects the **distinct**
thresholds and windows the whole file mentions — up to eight of each — and
assigns every one a feature bit. So ten rules mentioning 80% cost one
comparison per request between them, not ten. Exceeding eight distinct values of
either kind is a compile error, not a silent truncation.

`time_between` uses the **request's** local minute, which the serving node
supplies. This service does not know the subscriber's time zone, and inferring
one from the PLMN would be wrong for anyone roaming.

## Actions

```yaml
action:
  verdict: ALLOW | DENY | REDIRECT
  reason: PLAN_DEFAULT        # a stable code; appears in every decision
  inherit: all                # or [qos, ambr, quota, rating_group]
  qos_5qi: 9
  arp: 8
  ambr_ul: 1Mbps              # ambr_ul and ambr_dl must be set together
  ambr_dl: 1Mbps
  quota: 1GB
  quota_validity: 24h
  rating_group: 100
  redirect: portal            # required when verdict is REDIRECT
  flags: [throttled, quota_warning, roaming_restricted,
          tethering_blocked, off_peak_bonus]
```

**Inheritance.** `inherit` names the fields the subscriber's plan supplies.
Setting a field explicitly removes it from the inherit set automatically, so
"override the AMBR, inherit everything else" needs no ceremony:

```yaml
action: { verdict: ALLOW, inherit: all, ambr_ul: 1Mbps, ambr_dl: 1Mbps }
```

Inherited quota grants what is **left**, not the whole allowance — a serving
node treats it as a credit grant and comes back for more.

**`DENY` carries no authorization.** Whatever an action sets, a `DENY` decision
goes out with zeroed QoS, AMBR and quota, so a serving node that ignores the
verdict still cannot open a bearer from the reply.

## Units

| Kind | Accepted | Notes |
|---|---|---|
| Bytes | `20GB`, `512MiB`, `1_000_000`, `900B` | SI is powers of 10, IEC is powers of 2 |
| Rates | `50Mbps`, `1.5Gbps`, `1000` | bare numbers are kbps |
| Durations | `30d`, `4h`, `15m`, `900s`, `900` | bare numbers are seconds |
| Percentages | `80%`, `0.8`, `80` | all mean 80% |
| PLMN | `310-260`, `310260`, `234-15` | MCC is always 3 digits, MNC 2 or 3 |
| Time of day | `"02:00"` | quote it; 24-hour local time |

A suffix the parser does not recognize is an error, never a silently ignored
one. `10Furlongs` fails to load rather than becoming 10.

## What the compiler checks for you

- **Shadowed rules.** If an earlier rule tests a subset of a later rule's bits
  with the same values and covers its plans, the later rule can never fire. The
  compiler says so by id and priority. This is the most common policy authoring
  bug and it is completely silent at runtime.
- **Unknown names** — a DNN, plan, redirect, verdict, reason, RAT or condition
  that does not exist is an error with a line number.
- **Out-of-range values** — 5QI outside 1–255, ARP outside 1–15, a `REDIRECT`
  with no target, an AMBR set in only one direction.
- **Non-standardized 5QI** below the operator-specific range (128–254) is a
  warning, so `95` typed for `9` gets noticed.
- **Unknown top-level keys** are warnings, not errors: a forward-compatible key
  should not take the policy offline, but a typo should still be loud.

## Reloading

Write the file and either touch it (the control plane polls mtime) or:

```
curl -X POST localhost:9501/rules/reload
```

The swap is an atomic pointer store. In-flight requests finish against the old
rule set, the next request sees the new one, no request is dropped, and every
decision carries the `policy_version` that produced it.

**A file that fails to compile never goes live.** The previous rule set keeps
serving and the failure is reported on `/stats` and in the log with a line
number. The only reload that is refused for a reason other than a syntax error
is one that renames or reorders a plan, which needs a restart.

## Checking a rule before you ship it

`/explain` runs one request through the live policy and shows the decoded
feature word alongside the decision:

```
$ curl -s 'localhost:9501/explain?imsi=310260100003990&dnn=internet&rat=1'
{
  "features_decoded": "rat=NR dnn=internet status=ACTIVE home_plmn roaming_allowed
                       tethering_allowed quota_exhausted usage>=800permille",
  "rule_id": 61,
  "verdict": "ALLOW",
  "reason": "QUOTA_EXHAUSTED_THROTTLED",
  "ambr_dl_kbps": 1000,
  ...
}
```

Parameters: `imsi` (required), `imei`, `plmn`, `dnn`, `rat`, `qos_5qi`,
`minute`, `usage`, and the flags `tethering` and `emergency`.

For a change that should not alter behaviour, the golden corpus is the check:
`policy-gen-golden` regenerates 10,000 decisions and the diff is the review
artefact.
