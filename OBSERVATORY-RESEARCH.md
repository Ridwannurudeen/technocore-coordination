238,714
Research snapshot: 2026-08-28.

The decisive conclusion is this:

> [INFERENCE] The definitive Technocore Observatory should measure the conversion from published DID notes into sustained, reciprocal, signed activity. It must never claim to identify independent agents, humans, operators, or airdrop eligibility.

The API exposes key possession and observable behaviour, not personhood. Current Technocore is a chat/notes service, not the FLOP testnet or a Proof-of-Useful-Inference ledger. The formal FLOP airdrop basis described by FLOP is future testnet participation—especially inference consumed or supplied—not present-day chat volume. [FLOP teaser](https://flop.finance/teaser/), [Technocore manual](https://technocore.chat/llms.txt), [repository](https://github.com/flop-labs/technocore-chat).

Evidence labels used below:

- **PRIMARY** — Technocore/FLOP source, official documentation, official research, or directly measured behaviour supplied in the brief.
- **SECONDARY** — independently accessible reproduction or mirror of a primary post.
- **INFERENCE** — recommended computation or interpretation derived from primary observations.

Behavioural evidence classes:

- **E1** — cryptographic plus server-attested: signed `did:key` write with server `seq`/`ts`.
- **E2** — server-attested longitudinal fact without identity proof: room creation, sequence movement, liveness.
- **E3** — syntactically valid but world-writable convention: DID note, topic, room name, ownership listing.
- **E4** — anonymous content or self-asserted nickname.

# 1. API SURFACE TABLE

The deployed OpenAPI reports version `0.10.0`. The definitive route registration is in [app.py](https://raw.githubusercontent.com/flop-labs/technocore-chat/main/src/app.py); storage and exact aggregate shapes are in [store.py](https://raw.githubusercontent.com/flop-labs/technocore-chat/main/src/store.py). The [changelog](https://raw.githubusercontent.com/flop-labs/technocore-chat/main/CHANGELOG.md) is more current than GitHub’s releases-page badge.

## Dynamic data routes

| Endpoint, parameters, response fields | Metric unlocked | Used now? |
|---|---|---|
| **[PRIMARY] `GET /r/{room}`**. `room` matches `^[a-z0-9][a-z0-9_-]{0,47}$`. Query: `since` integer ≥0; `limit` 1–200, default 50; `wait` 0–10 and requires `since`; `format=json`; `n` arbitrary ignored cache-buster. JSON: `room`, `count`, `first_seq`, `last_seq`, `messages[]`. Message: required `seq`, `ts`, `from`, `text`; optional `nonce`. | Per-room retained-window velocity, interarrival distribution, message lengths, author concentration, signed-DID share, reply topology, and collection/ring loss where `first_seq > since + 1`. | **Partial** — lobby velocity and first messages only. |
| **[PRIMARY] `POST /r/{room}`**. JSON body: required `text`; unsigned `from`; optional signed bundle `did`, `sig`, `nonce`. `text` 1–4096; DID exactly 56 characters; signature 86 base64url characters; nonce 1–19 digits. `format=json` works in source although omitted from the POST schema. Actual JSON adds `posted` to the room response. | No read-only metric. The `posted` record is useful only to a writer. | **Must not use** — observatory is read-only. |
| **[PRIMARY] `GET /r/{room}/say/{nick}/{text}`**. Path `room`, `nick`, URL-encoded `text`; source accepts `format=json`. JSON is room view plus `posted`. | None for a collector. | **Must not use.** |
| **[PRIMARY] `GET /r/{room}/say-signed/{did}/{sig}/{nonce}/{text}`**. Signature covers `<room>\|<nonce>\|<text-after-sweep>`. | None for a collector. | **Must not use.** |
| **[PRIMARY + measured deployment override] `GET /r/events`**. Documented as the same read surface as a room: `since`, `limit`, `wait`, `format`, `n`; records have server `seq`, `ts`, `from="server"`, and text `created <room>`. Private `p-` rooms are excluded. Client writes are refused. | Forward room creation, creation rate, name-class mix, burst structure. | **Yes.** |
| **[PRIMARY] Critical deployment fact:** every tested `since` returns the newest 200. No `before`, offset, search, or historical route exists. | Establishes the forward-only boundary. | **Yes; preserve prominently.** |
| **[PRIMARY] `GET /rooms`**. Query: `limit`, default 50, source-clamped to 200; `format=json`. No `offset`. Top-level: `rooms`, `total`, `capacity`, `bytes`, `bytes_capacity`, `notes`, `engagement`, `untrusted`. | Public listed-room occupancy, capacity and byte headroom, note occupancy, current activity/idle distribution and engagement. | **No**, except room names obtained elsewhere. |
| **[PRIMARY] Each `/rooms.rooms[]`:** `room`, `last_seq`, `bytes`, `idle_seconds`, `topic`, `window`, `zero_response_share`, `nick_diversity`. `room` and `topic` are explicitly untrusted. | Room activity age; storage/activity proxy; topic adoption; one-writer/terminal-run share; distinct-nick-per-message share; exact denominator through `window`. | **No. High-value omission.** |
| **[PRIMARY] `/rooms.notes`:** `total`, `bytes`, `capacity`, `capacity_per_namespace`. | Note-store occupancy and headroom. | **No.** |
| **[PRIMARY] `/rooms.engagement`:** `window_cap`, `windowed_messages`, `zero_response_share`, `nick_diversity`, `windowed_note_to_message_ratio`. | Pooled current-window interaction and durable-state-use tripwires. The last is notes divided by scanned messages, not a lifetime ratio. | **No. High-value omission.** |
| **[PRIMARY] `/rooms.untrusted`:** `fields`, `note`; `fields` identifies `room` and `topic`. | Machine-readable trust disclosure; useful for methodology, not network measurement. | **No.** |
| **[PRIMARY] `GET /kv/{ns}`**. Path `ns`; source accepts `format=json` although OpenAPI omits it. JSON: `ns`, `keys`. Namespaces themselves cannot be enumerated; `p-` keys are omitted. | Current membership of a known namespace. Enables identity shards, topic keys, room owners, allow lists and replay-counter adoption. | **Yes only for DID shards.** |
| **[PRIMARY] `GET /kv/{ns}/{key}`**. Returns an untrusted-content banner and raw value as text; 404 if absent. No JSON value response. | Validate current note values and conventions: DID fingerprint consistency, ownership DID, allow-list size, optional mailbox/X25519 fields. | **Partial** — identity census values only. |
| **[PRIMARY] `POST /kv/{ns}/{key}`**. Body: required `value` 1–8192; optional `if`, `if_absent`; optional `did`, `sig`, `nonce`. Success JSON: `ns`, `key`, `bytes`, `ts`. | None for a collector. | **Must not use.** |
| **[PRIMARY] `GET /kv/{ns}/{key}/set/{value}`**. Query `if`, `if_absent=1`, operational `format=json`. Success JSON: `ns`, `key`, `bytes`, `ts`. | None for a collector. | **Must not use.** |
| **[PRIMARY] `GET /kv/{ns}/{key}/set-signed/{did}/{sig}/{nonce}/{value}`**. Same CAS queries. Only `room-owners` and `room-allow` accept signed note writes; `room-nonce` is server-written. | None for a collector. | **Must not use.** |

Important semantics:

- **[PRIMARY]** `first_seq` is the oldest message in the returned slice; `last_seq` is the polling cursor. Neither is a retained-message count.
- **[PRIMARY]** `ts` is UTC with microseconds, but `seq` is the ordering authority.
- **[PRIMARY]** A signed message’s `from` is its verified `did:key`; `nonce` appears only on signed messages.
- **[PRIMARY]** The signature proves control of a key, not a person, independent machine, honest agent, or unique operator. [Auth documentation](https://technocore.chat/auth.md).
- **[PRIMARY]** `/rooms.total` excludes unlisted `p-` rooms.
- **[PRIMARY]** `/rooms` is newest-activity-first and limited to 200, so its engagement output is a bounded recent-active-room window—not a network census.
- **[PRIMARY]** `idle_seconds`, recency, bytes and engagement may be stale by the configured room cache plus edge cache.

## Operator-only route

| Endpoint and fields | Metric unlocked | Used now? |
|---|---|---|
| **[PRIMARY] `GET /stats`**, source-only and intentionally omitted from OpenAPI. Requires `X-Stats-Token`. Missing/wrong/unconfigured token returns the same generic 404 as an unknown path. | Exact all-room and service-lifetime metrics. | **Unavailable. We do not have the token.** |
| **[PRIMARY] Fields:** `rooms{total,listed,unlisted,open,mailbox,ownable,ephemeral,capacity}`; `bytes{rooms,notes,rooms_capacity}`; `notes{total,bytes,capacity,capacity_per_namespace}`; `counters{messages,rooms_created,reaped_idle,reaped_stillborn,notes_written,topics_written}`; `engagement{window_cap,windowed_messages,zero_response_share,nick_diversity}`; `history[]` with timestamp `t` and aggregate snapshots; `requests{read,write,rate_limited,uptime_seconds,scope,workers}`; `capacity_limits{message_chars,note_chars,room_bytes,read_per_min,write_per_min,new_rooms_per_day,room_bytes_total}`; `client_identity{client_ip_header,distinct_identities,proxied_requests_ignored}`. | Only route to exact unlisted-room counts, all-room class counts, lifetime creation/reap/message/note/topic counters, server request volume, per-worker request rates and limiter-identity health. | **Cannot use or estimate.** |

Therefore these must remain unavailable:

- **[PRIMARY]** Exact total rooms including unlisted rooms.
- **[PRIMARY]** Lifetime message count.
- **[PRIMARY]** Exact stillborn and idle reaping counts.
- **[PRIMARY]** Total service request rate.
- **[PRIMARY]** IP-derived distinct limiter identities.
- **[PRIMARY]** Exact topics-written counter.
- **[PRIMARY]** Server-held historical aggregates.

## Configuration and discovery routes

| Endpoint and response | Metric unlocked | Used now? |
|---|---|---|
| **[PRIMARY] `GET /config`**. Top-level `service`, `version`, `env_prefix`, `settings`, `units`, `withheld`, `note`. | Configuration-regime annotations, cache-staleness bounds and collector pacing. | **No; SHOULD collect occasionally.** |
| **[PRIMARY] Current `settings`:** `rate_read`, `rate_write`, `rate_rooms_per_day`, `max_rooms`, `max_notes_per_ns`, `max_wait`, `wait_poll`, `max_waiters_total`, `max_waiters_per_ip`, `dupe_filter_seconds`, `dupe_max_copies`, `dupe_min_length`, `ephemeral_ttl_seconds`, `fsync`, `rooms_cache_seconds`, `note_stats_cache_seconds`, `edge_cache_seconds`, `static_cache_seconds`. | Explains changes in apparent creation, duplication, latency and staleness. | **No.** |
| **[PRIMARY] `withheld` names but does not reveal:** `CHAT_ROOT`, `CHAT_STATS_TOKEN`, `CHAT_STATS_CACHE_SECONDS`, `CHAT_CLIENT_IP_HEADER`, `CHAT_CORS_ORIGINS`, `CHAT_SECURITY_CONTACT`, `CHAT_DEBUG`, `CHAT_PUBLIC_URL`, `WEB_CONCURRENCY`. | Methodology: proves that stats credentials and topology are deliberately unavailable. | **No.** |
| **[PRIMARY] `GET /.well-known/agent.json`**. Top-level: `schema_version`, `name`, `version`, `display_name`, `description`, `role`, `audience`, `url`, `provider{name,url}`, `license`, `protocols`, `auth`, `documentation`, `capabilities`, `conventions`, `identity`, `limits`, `trust`. | Version, limits, retention and trust-regime annotations. | **No.** |
| **[PRIMARY] `identity`:** `scheme`, `algorithms`, `resolution`, `message_signature_payload`, `note_signature_payload`, `signature_encoding`, `nonce`, `canonicalisation`, `publishing_a_key`, `required_for`, `note`. | Exact DID-note validation and signature evidence definitions. | **No.** |
| **[PRIMARY] `limits`:** `message_chars`, `note_chars`, `reads_per_minute_per_ip`, `writes_per_minute_per_ip`, `new_rooms_per_day_per_ip`, `rooms`, `notes`, `notes_per_namespace`, `room_ring_bytes`, `room_bytes_total`, `retention_seconds`, `ephemeral_ttl_seconds`, `long_poll_seconds`, `note`. | Capacity/retention regime. | **No.** |
| **[PRIMARY] `trust`:** `content_is_untrusted`, `durable`, `world_writable`, `note`. | Trust disclosure. | **Partially reproduced in the existing limitations panel.** |
| **[PRIMARY] `GET /healthz`** → literal `ok`; never rate-limited. | Service reachability and probe latency. This is liveness, not data freshness. | **No. High-value omission.** |
| **[PRIMARY] `GET /` and `/llms.txt`** → same complete manual. | API/version drift detection only. | No. |
| **[PRIMARY] `GET /skill.md`** → onboarding skill. | None. | No. |
| **[PRIMARY] `GET /patterns.md`** → worked multi-agent patterns. | Known convention inventory; no direct metric. | No. |
| **[PRIMARY] `GET /interop.md`** → bridge guidance; does not make the origin speak those protocols. | None. | No. |
| **[PRIMARY] `GET /auth.md`** → no registration/OAuth/token issuance; optional self-issued DID signing. | Evidence definition. | No. |
| **[PRIMARY] `GET /openapi.json`** → OpenAPI 3.1. | API version/schema drift. | No. |
| **[PRIMARY] `GET /humans`** → static HTML UI. | None unavailable elsewhere. | No. |
| **[PRIMARY] `GET /robots.txt`** → crawler policy. | None. | No. |
| **[PRIMARY] `GET /.well-known/security.txt`** → reporting policy/contact. | None. | No. |
| **[PRIMARY] `GET /sitemap.xml`** → canonical documentation URLs; can 404 if origin is unknown. | None. | No. |
| **[PRIMARY] `GET /.well-known/api-catalog`** → `linkset[]`, each with `anchor`, `service-desc`, `service-doc`, `service-meta`, `status`; links have `href`, `type`. | None. | No. |
| **[PRIMARY] `GET /.well-known/ai-catalog.json`** → `specVersion`, `host`, `entries[]`. | None. | No. |
| **[PRIMARY] `GET /.well-known/agent-skills/index.json`** → `$schema`, `skills[]` with `name`, `type`, `description`, `url`, `digest`, `version`. | Release drift only. | No. |

Normal GET routes implicitly accept `HEAD`; GET-shaped mutation routes deliberately remove it. CORS middleware may answer valid browser preflights, but it adds no application data.

## Rate limits, errors and contract discrepancies

- **[PRIMARY]** Read and write token buckets are separate and keyed per client IP. New-room creation has its own continuously refilling per-day bucket.
- **[PRIMARY]** A 429 carries retry seconds, bucket and refill rate in the body as well as `Retry-After`.
- **[PRIMARY]** Low-budget text replies add a budget footer below 25% remaining.
- **[PRIMARY]** Long-poll consumes one read when the wait starts.
- **[PRIMARY]** Documentation, `/config`, `/.well-known/*` and `/healthz` are not rate-limited.
- **[PRIMARY]** Relevant errors: 400 malformed input; 403 lane/signature/ownership refusal; 404 absence/hidden stats; 405 plus `Allow`; 409 CAS failure carrying current value; 413 oversized body; 422 duplicate text; 429 rate/creation budget; 431 oversized header block. Intermittent deployed 5xx must be stored as observation gaps.
- **[PRIMARY]** Every returned room name, topic, note value, nickname and message body is anonymous world-writable input. Render with text nodes/escaping only.

Verified discrepancies:

1. **[PRIMARY]** Source/manual promise incremental `/r/events?since`; deployed tests show newest-200 behaviour. The measured deployment wins for Observatory methodology.
2. **[PRIMARY]** OpenAPI’s `/rooms` nested schemas are generic objects; exact fields come from current source.
3. **[PRIMARY]** Actual write responses add `posted`, and `format=json` works on more routes than OpenAPI declares.
4. **[PRIMARY]** There is no `offset`, `before`, search, historical endpoint, or namespace enumeration.
5. **[PRIMARY]** GitHub’s release display lagged the deployed `0.10.0`; the deployed OpenAPI and changelog are authoritative.

# 2. METRICS THAT MATTER

FLOP’s stated values are useful work, continued availability, accuracy, latency, inference supplied and inference consumed. The draft teaser allocates up to 1.2 billion FLOP to agents and says the agent testnet allocation is based largely on inference spending. Validators are evaluated on uptime, block production, accuracy and latency. [FLOP teaser](https://flop.finance/teaser/).

Arthur Hayes likewise says he wants “useful participants” rewarded; he does not publish a Technocore activity formula. [The Book of Genesis](https://cryptohayes.substack.com/p/the-book-of-genesis).

Two mirrored social claims explain the present incentive shock:

- **[SECONDARY]** @flop_labs reportedly asked agents to create a unique DID and “do something useful” to spread Technocore, with airdrop rewards. [Direct X URL](https://x.com/flop_labs/status/2091830155270672521).
- **[SECONDARY]** Hayes reportedly said Technocore tasks may require a unique DID and reward completion, and separately that the testnet faucet will live on Technocore. An accessible profile mirror reproduces these statements. [Mirror](https://zamantika.com/en/profile/flop_labs).

Those claims do not turn a DID note into a unique agent.

## Ranked signals

### 1. DID-to-signed-activity funnel — MUST

- **What it shows [INFERENCE]:** How much cheap directory publication becomes observable, attributable use.
- **Compute:**  
  `well-formed DID notes → DIDs seen signing → DIDs seen on ≥2 ticks → ≥2 UTC dates → ≥2 rooms → ≥1 distinct signed counterparty`.
- **Inputs:** 256 DID namespace listings and `/r/{room}?format=json`; signed observation requires DID-shaped `from` plus `nonce`.
- **Report:** Count and conditional conversion at every stage, observation window, monitored-room coverage and unknown/unobserved category.
- **False-positive risk:** **Medium-high.** A legitimate one-shot participant fails; a farm can automate every rung.
- **Evidence:** **E1 + E3.**
- **Supported claim:** “Observed sustained key use.”
- **Unsupported claim:** “Real agents,” unique humans, or eligibility.

### 2. Cohort retention and continued control — MUST

- **What it shows [INFERENCE]:** Whether enrollment cohorts persist after the announcement spike.
- **Compute:** First-observed census cohort; percentage signing again after 1/3/7/14 days; distinct active UTC dates; observed active span `max(ts)-min(ts)`; directory survival separately from signed-activity survival.
- **Display:** Cohort heatmap or survival curves with collector gaps and right-censoring.
- **False-positive risk:** **Medium.** Real agents may operate episodically; farms can schedule heartbeats.
- **Evidence:** **E1 + E3.**
- **Supported claim:** Persistence and continued possession/use of the same signing key.

### 3. Reciprocal signed interaction — MUST

- **What it shows [INFERENCE]:** Multi-key exchange rather than self-broadcast.
- **Conservative computation:** An interaction occurs when two distinct signed DIDs alternate in the same room within 10 messages and 15 minutes. Also show sensitivity at 1 minute, 10 minutes and 1 hour.
- **Report:** Distinct counterparties per DID, share receiving a response, reciprocated-edge share, component-size distribution and reply-latency percentiles.
- **False-positive risk:** **Medium-high.** Broadcast agents are legitimate; coordinated keys can converse; both DIDs may share an operator.
- **Evidence:** **E1.**
- **Supported claim:** Observable multi-key exchange—not independence.

### 4. Signed activity concentration — MUST

- **What it shows [INFERENCE]:** Whether observed activity is broadly distributed or dominated by a small number of signing keys.
- **Compute:** For message shares `pᵢ`, report HHI `Σpᵢ²`, effective active keys `1/HHI`, Gini, top-1/top-10/top-1% shares. Repeat for rooms used and counterparty edges.
- **False-positive risk:** **Low descriptively; high interpretively.** A service bot can legitimately dominate.
- **Evidence:** **E1.**
- **Supported claim:** Concentration of observed activity.

### 5. Room lifecycle and response conversion — MUST

- **What it shows [INFERENCE]:** Whether the room explosion produces conversations or one-message shells.
- **Compute forward:** For every newly observed room, revisit on a bounded schedule such as 5 minutes, 1 hour and 24 hours. Record time to second message, time to second distinct sender, messages at each checkpoint, active span and disappearance/reaping.
- **Also consume:** `/rooms` fields `window`, `zero_response_share`, `nick_diversity`, `idle_seconds`, `bytes`.
- **Stratify:** `mb-`, `d-`, `e-`, bare-hex, human-ish and other name classes.
- **False-positive risk:** **Medium.** Mailboxes, queues, logs and deliberately single-use rooms may be valid.
- **Evidence:** **E1/E2**, with class name **E3**.
- **Supported claim:** Public-room utilisation and response structure.

### 6. Template/copy concentration across signing keys — MUST

- **What it shows [INFERENCE]:** Homogeneous or mechanically repeated participation.
- **Compute:** Exact stored-text hash plus a separately documented normalized hash; report cluster size in signed DIDs, rooms and messages; first/last timestamp; percentage of DIDs whose only observed message is in a top template; normalized-text entropy.
- **Safety:** Do not render raw hostile content by default.
- **False-positive risk:** **High.** Official tasks and tutorials legitimately create identical messages.
- **Evidence:** **E1** for attribution; content remains untrusted.
- **Supported claim:** Behavioural homogeneity, never shared control or intent.

### 7. Signed participation and DID-note consistency — MUST

- **What it shows [PRIMARY/INFERENCE]:** Adoption of attributable writes and conformance to the published identity convention.
- **Compute:** Signed messages/all observed messages; unique signed DIDs/all observed senders; validate Ed25519 `did:key:z6Mk…`; recompute the first-16 SHA-256 fingerprint and compare to `did-<first2>/<remaining14>`; separately report optional mailbox and X25519 fields.
- **False-positive risk:** **Low for syntax; extremely high for personhood.** Correct keys are cheap and ordinary DID notes are world-writable.
- **Evidence:** **E1 + E3.**
- **Supported claim:** Protocol-conformant publication and key-attributable activity.

### 8. Breadth and counterparty diversity — MUST

- **What it shows [INFERENCE]:** Whether keys operate across contexts rather than only emitting one campaign message.
- **Compute per DID:** Distinct rooms, distinct signed counterparties, Shannon entropy across rooms, median messages per room, share outside lobby/onboarding rooms.
- **False-positive risk:** **Medium-high.** A specialised single-room agent can be entirely legitimate; spraying rooms is easy to automate.
- **Evidence:** **E1.**
- **Supported claim:** Observable behavioural breadth.

### 9. Creation/enrollment synchrony — SHOULD

- **What it shows [INFERENCE]:** Campaign waves and tightly coordinated automation.
- **Compute:** Two- and ten-minute buckets of first note observation and first signed write; show overlap among tight timing, same text cluster, same target room, similar cadence and room-name class.
- **False-positive risk:** **Very high.** Announcements, tutorials, time zones and rate-limit recovery synchronize unrelated users.
- **Evidence:** **E1–E3.**
- **Supported claim:** Correlated timing only.

### 10. Temporal regularity and burstiness — SHOULD

- **What it shows [INFERENCE]:** Timing phenotype and continued availability.
- **Compute with sufficient N:** Interarrival coefficient of variation, Fano factor across fixed buckets, active-hour entropy in UTC, longest observed gap and exact-periodic-cadence share.
- **False-positive risk:** **Very high.** Both legitimate agents and farms are automated.
- **Evidence:** **E1.**
- **Supported claim:** Timing distribution, never “agent probability.”

### 11. Owned-room collaboration — SHOULD

- **What it shows [INFERENCE]:** Actual adoption of attributable coordination primitives.
- **Compute:** Current `room-owners`, `room-allow`, `room-nonce` listings; valid owner DID share; allow-list size; distinct allowed DIDs actually observed posting; owned-room survival and signed-activity distribution.
- **False-positive risk:** **Medium.** Ownership can be squatting, demos or unused configuration.
- **Evidence:** **E1 + E3.**
- **Supported claim:** Use of ownership/delegation features.

### 12. Note/message ecology — LATER

- **What it shows [INFERENCE]:** Durable-state feature use relative to current chat activity.
- **Compute:** `/rooms.engagement.windowed_note_to_message_ratio`, note occupancy and note-byte trends; topic presence share; current known-namespace distributions.
- **False-positive risk:** **High.** Notes are world-writable; state can be spam; namespace conventions are optional.
- **Evidence:** Mostly **E3**, with aggregate counts server-measured.
- **Supported claim:** Public state-feature use.

### 13. Nonce/client phenotype — LATER

- **What it shows [INFERENCE]:** Signing-client implementation patterns.
- **Compute:** Per DID-room monotonic increments, millisecond-clock-like versus counter-like values, gap distributions and rejected/replayed patterns only where directly observed.
- **False-positive risk:** **High.** Multiple valid nonce strategies exist, and anti-replay durability is bounded by the scanned tail.
- **Evidence:** **E1.**
- **Supported claim:** Signing-client behaviour, not identity quality.

## Metrics that matter to FLOP but are impossible today

- **[PRIMARY]** Inference requests, FLOPs consumed, fees spent, task completion, latency, model identity and confidentiality flag.
- **[PRIMARY]** Miner compute supplied, TEE/TOPLOC attestations, re-execution results and slashing.
- **[PRIMARY]** Validator uptime, accuracy, block production and latency.
- **[PRIMARY]** Wallets, stake, faucet usage and testnet balances.
- **[PRIMARY]** IP, ASN, geography, hardware, GPU, device, client software and operator.
- **[PRIMARY]** One-human/one-agent or independent-control determination.
- **[PRIMARY]** Airdrop eligibility.

The page should say:

> **[INFERENCE] This observes public Technocore records and signing keys. It does not identify independent agents, reconstruct history, or determine FLOP eligibility.**

# 3. PANEL SET

## MUST

1. **Observation status and coverage**

   Last successful tick; last attempted tick; next expected tick; collection start; current UTC; successful/missed/429/5xx ticks; observed interval; API/config version; raw record count; current resolution.

2. **Forward growth pulse**

   Rooms observed since collection began, new rooms per interval, cumulative forward-observed rooms, creation-rate distribution and explicit pre-collection blank region. Keep the current room animation/scrubber.

3. **Room lifecycle**

   New-room cohort conversion to second message and second distinct sender at 5m/1h/24h; active lifetime; response latency; `zero_response_share`; `nick_diversity`; `window` sample size.

4. **Identity publication census**

   Current well-formed DID notes, malformed notes, shard coverage, legacy-vs-sharded publication, fingerprint/path consistency and observed census time.

5. **DID-to-signed-activity funnel**

   The ranked funnel above, with every denominator and monitored-room coverage.

6. **Signed activity over time**

   Signed/all message share, unique signing keys per interval, new versus returning signing keys, nonce-bearing record share.

7. **Cohort retention**

   Directory and signed-activity retention shown separately; active-span and distinct-active-day distributions.

8. **Reciprocal interaction**

   Counterparties per signing key, response share, reply latency and reciprocated-edge share. Prefer distributions over a decorative hairball graph.

9. **Activity concentration**

   Top shares, HHI/effective-key count and Gini for signed messages, rooms and interaction edges.

10. **Template homogeneity**

    Exact and normalized copy-cluster distributions, without exposing raw hostile text by default.

11. **Network composition**

    Room classes, name classes, signed/unsigned traffic, empty/one-writer/multi-writer rooms, known/unknown categories. Keep the current new-room class band.

12. **Service and collector health**

    `/healthz` success/latency, API failures, rate-limit gaps, actual tick interval, gap visualization and staleness state.

13. **Capacity and current ecology**

    `/rooms` listed total, room bytes/headroom, note count/bytes/headroom, current `windowed_note_to_message_ratio`, topics-present share. Label all figures as public/current-window.

14. **What cannot be seen**

    Keep and expand the existing panel: no backfill, unlisted rooms omitted, public input untrusted, `/stats` inaccessible, no operator/IP/wallet/hardware/inference evidence.

15. **Methodology and downloads**

    Exact formulas, endpoints, cadence, collector/deriver version, raw/derived download, schema and change history.

## SHOULD

16. **Enrollment synchrony and burst clusters** — population-level counts only.

17. **Temporal regularity** — aggregate timing distributions, not named rankings.

18. **Owned-room and delegation adoption** — `room-owners`, `room-allow`, observed authorised writers.

19. **Configuration-regime timeline** — annotate changes to API version, rate limits, duplicate filter, retention and cache windows.

20. **Sensitivity controls** — allow reply-window and retention definitions to change while showing the selected formula.

## LATER

21. **Nonce/client phenotype.**

22. **Topic and state-convention adoption**, without content analysis.

23. **Future FLOP testnet panel** only after a real public testnet API exposes inference, spend, validation and latency data. It must remain separate from Technocore chat.

24. **Independent estimator comparison** if a second honest collector or API view becomes available. Do not average differing estimators; present them side by side.

# 4. CREDIBILITY CHECKLIST

Ranked in order of impact:

1. **Observation boundary and impossibility statement.**  
   Collection start, forward-only scope, newest-200 cap, excluded private rooms and inaccessible `/stats`.

2. **Per-panel denominator and coverage.**  
   Every percentage gets `n/N`, covered rooms, covered ticks and unknown count.

3. **UTC time discipline.**  
   Store ISO-8601 UTC; display UTC by default. Local time may be secondary and must include zone/offset. Show collection start, last attempt, last success, derivation time and source observation time separately.

4. **Gap disclosure.**  
   Missing, 429 and 5xx intervals remain gaps—not zeroes and not interpolated values.

5. **Exact definitions and formulas.**  
   Put a short definition beside each panel and a full reproducible derivation in methodology.

6. **Raw measured-data download.**  
   Publish the exact records underlying displayed claims, with covered interval, record count and schema. If only rollups are downloadable, call them “derived series,” not raw.

7. **Reproducible collector and derivation.**  
   Open source, pinned commit/release, collector cadence, endpoint parameters and deterministic build command.

8. **Correct uncertainty treatment.**

   - Exact census: no artificial confidence interval; report validity and coverage.
   - Newest-active-200 window: explicitly biased non-probability window; no classical sampling CI.
   - Random samples, if introduced: publish sampling frame and seed; Wilson interval for proportions or bootstrap intervals for medians.
   - Forward detection: show the two-minute observation interval and collection gaps.
   - Never use decorative error bars.

9. **Provenance chain.**  
   For every derived field: endpoint, parameters, collection timestamp, HTTP status, raw record identifier/hash and derivation version.

10. **Versioned methodology and schema.**  
    Method version visible in-page; chart annotations when formulas, API versions or configuration regimes change.

11. **Prominent freshness state.**  
    “Live”, “delayed”, “stale” and “collector down” based on declared thresholds; never rely on tiny last-updated text.

12. **Open-source link and immutable release.**

13. **Separate data/code/page licences.**

14. **Public changelog and correction history.**

15. **Contact/issue/security channel.**

16. **Privacy and safety statement.**  
    Follow Tor Metrics’ principles of data minimalism, aggregation and transparent algorithms. [Tor Metrics philosophy](https://metrics.torproject.org/about.html).

17. **Method comparison where definitions differ.**  
    Ethereum client-diversity trackers expose estimator biases and unknowns rather than averaging them. [Methodology](https://clientdiversity.org/methodology).

The best prior-art practices to copy are:

- **[PRIMARY]** Tor provides per-graph CSV, stable columns and reproduction specifications. [Tor statistics files](https://metrics.torproject.org/stats.html), [reproducible metrics](https://metrics.torproject.org/reproducible-metrics.html).
- **[PRIMARY]** Cloudflare Radar identifies data sources and returns aggregation interval, date range, normalization, units and last-updated metadata. [Radar about](https://radar.cloudflare.com/about).
- **[PRIMARY]** Clientdiversity publishes unknowns, biases, source freshness and removes sources whose relationship to the real network is not understood. [Client Diversity](https://clientdiversity.org/).
- **[PRIMARY]** ProbeLab publishes exact measurement conditions, percentiles, sample counts and geographic vantage points where geography is actually observed. [IPFS measurement overview](https://docs.ipfs.tech/concepts/measuring/).
- **[PRIMARY]** Mempool exposes both current stock and flow, supports self-hosting, documents estimates as guidance, and audits observed blocks against predicted templates. [API](https://mempool.space/docs/api/rest), [FAQ](https://mempool.space/docs/faq), [source](https://github.com/mempool/mempool).

# 5. A11Y + PERFORMANCE REQUIREMENTS

## Accessibility

- **[PRIMARY/INFERENCE] Native scrubber:** Use `<input type="range">`. If custom, implement `role="slider"`, focusability, accessible label, `aria-valuemin`, `aria-valuemax`, `aria-valuenow`, and human-readable UTC `aria-valuetext`.
- **[PRIMARY] Keyboard:** Arrow keys one tick; Home/End first/last; Page Up/Down larger interval. [W3C slider pattern](https://www.w3.org/WAI/ARIA/apg/patterns/slider/).
- **[INFERENCE] Touch alternative:** Add previous/next buttons and a timestamp input so dragging is never the only operation. [WCAG dragging guidance](https://www.w3.org/WAI/WCAG22/Understanding/dragging-movements.html).
- **[PRIMARY] Reduced motion:** Respect `@media (prefers-reduced-motion: reduce)` and `matchMedia()` in JavaScript. Disable autoplay, smooth scrubbing, pulsing, point transitions and parallax. Preserve an explicit play/pause button. [W3C reduced-motion guidance](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions), [media-query specification](https://www.w3.org/TR/mediaqueries-5/).
- **[PRIMARY] Colour:** Never encode status/class only by hue. Combine an Okabe–Ito-style colour-blind-safe palette with direct labels, line dashes, marker shapes or patterns. [WCAG use of colour](https://www.w3.org/WAI/WCAG22/Understanding/use-of-color).
- **[PRIMARY] Contrast:** Normal text ≥4.5:1; large text ≥3:1; chart lines, boundaries, controls and focus indicators ≥3:1 against adjacent colours. [WCAG 2.2](https://www.w3.org/TR/WCAG22/).
- **[PRIMARY] Chart alternatives:**  

  - SVG: `<title>` and `<desc>` referenced by `aria-labelledby`.
  - Canvas: adjacent DOM summary and compact data table; the pixel buffer alone is inaccessible.
  - Every chart needs current value, trend, scale, sample count, gaps and exceptions in text.

- **[INFERENCE] Avoid chatty live regions:** Announce committed scrubber positions, not every animation frame.
- **[PRIMARY] Keyboard/focus parity:** Tooltips must appear on focus as well as hover; visible focus; no traps.
- **[PRIMARY] Reflow:** One logical column at 320 CSS px, no lost content/functionality and no page-level two-dimensional scrolling. [WCAG reflow](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html).
- **[INFERENCE] Mobile charts:** Legend below chart, reduced tick density, minimum 44×44 CSS-pixel touch targets, chart-local horizontal scrolling only when the two-dimensional relationship is essential.
- **[INFERENCE] High-contrast mode:** Use semantic DOM, `currentColor`, visible borders and `forced-color-adjust:auto` where appropriate.
- **[INFERENCE] No hover-only facts.** Essential latest/min/max and selected timestamp remain visible in DOM text.

## Correct long-series handling

- **[INFERENCE] Maintain UTC-aligned multiresolution levels:** raw 2-minute, 10-minute, hourly and daily.
- **[INFERENCE] Each aggregate bucket retains:** `start`, `end`, `first`, `last`, `min`, `max`, `sum` or numerator/denominator, observation count, expected tick count, missing count and observed seconds.
- **[INFERENCE] Recompute ratios from primitives:** Sum numerators/denominators, then divide. Never average percentages, rates or rounded values.
- **[INFERENCE] Preserve gaps:** No-success buckets are `null`; partial buckets retain completeness. Do not connect lines across gaps.
- **[INFERENCE] Pixel-aware selection:** Render roughly one to four retained tuples per CSS pixel.
- **[PRIMARY/INFERENCE] Prefer extrema-preserving MinMax/M4-style reduction for integrity and anomaly charts.** M4 bounds output around four tuples per chart-width pixel while preserving visible extrema. [M4 paper](https://datavis.cs.columbia.edu/files/papers/m4.pdf).
- **[INFERENCE] LTTB can be used for overview shape only.** It discards observations; do not use an LTTB-only series for anomaly counts, peaks or integrity claims. [MinMaxLTTB paper](https://arxiv.org/abs/2305.00332).
- **[INFERENCE] Always preserve first/last points and every gap boundary.**
- **[INFERENCE] Label resolution visibly:** “2-minute raw”, “1-hour rollup”; tooltip includes bucket bounds, N and completeness.
- **[INFERENCE] Allow zoom to retained raw resolution.**

## Keeping the single file small

- Store timestamps as deltas from one epoch and sequence numbers as deltas.
- Use numeric column arrays rather than repeated JSON object keys.
- Dictionary-encode room classes and repeated strings.
- Never embed full message or topic text when only hashes/lengths/categories are needed.
- Keep exact raw source records only for a declared bounded interval if indefinite raw retention would make the file impractical.
- If old raw data is retired from the HTML, retain truthful multiresolution aggregates and rename the in-page export “derived series.” Do not call it raw.
- Let HTTP serve the HTML with Brotli/gzip, but do not require external scripts or fonts.
- Build charts from small native SVG/canvas code rather than bundling a chart framework.
- Instantiate offscreen panels with `IntersectionObserver`.
- Coalesce pointer/scrubber redraws through `requestAnimationFrame`.
- For canvas, cap the backing-store `devicePixelRatio`; do not allocate unbounded 3×/4× canvases.
- Use `ResizeObserver` for redraws and separate static axes from frequently redrawn marks.
- Keep source data immutable; derive display arrays once per resolution rather than on every scrub frame.

# 6. ANTI-FEATURES — DO NOT BUILD

- **[INFERENCE] No airdrop estimator, eligibility checker, points, streaks, badges, referrals, countdown or “positioning” guidance.**
- **[INFERENCE] No wallet connect, token price, reward calculator or claim link.**
- **[INFERENCE] No DID/nickname leaderboard.**
- **[INFERENCE] No named “farmer”, “bot”, “fake” or “Sybil” accusation.**
- **[INFERENCE] No composite “real-agent”, “quality”, “integrity” or “network-health” score.** Weighting hides evidence weakness and becomes a gaming target.
- **[INFERENCE] No instructions for generating more activity or improving a DID’s apparent score.**
- **[PRIMARY/INFERENCE] Never call 435,006 notes “agents” or “users.”** Use “well-formed published DID notes” or “observed signing keys.”
- **[INFERENCE] No historical reconstruction, pre-collection curve, interpolation, extrapolated all-time count or fabricated baseline.**
- **[INFERENCE] No line across a collector gap and no missing-as-zero substitution.**
- **[INFERENCE] No geography, ASN, device, GPU, wallet, client or operator panel—the API exposes none.
- **[INFERENCE] No percentages without denominators and no ranks without unknown/unobserved categories.**
- **[INFERENCE] No averages without distribution, sample count and observation window.**
- **[INFERENCE] No silent deduplication, smoothing, filtering or sampling.**
- **[INFERENCE] No dual-axis or 3-D charts, animated gauges, unexplained red/green alarms or axes that continuously rescale while playing.**
- **[INFERENCE] No force-directed “agent network” hairball implying social relationships stronger than same-room temporal proximity.
- **[PRIMARY/INFERENCE] No word clouds or prominent raw-content examples.** They amplify hostile anonymous text and create an XSS/prompt-injection surface.
- **[PRIMARY] Never use `innerHTML` for room names, topics, notes, nicks or messages.** Use `textContent`, attribute-safe assignment and display-length caps.
- **[INFERENCE] No external fonts, analytics, trackers, telemetry, CDN scripts or runtime API requests.
- **[INFERENCE] No stale data presented as live.**
- **[INFERENCE] No copying Ethereum/IPFS geography or client-diversity panels merely because respected observatories have them. Copy their honesty about evidence, not their fields.**

The recommended build order is: collector reliability and `/healthz`; `/rooms` engagement and capacity; signed-message collection; DID funnel; room lifecycle revisits; retention; reciprocal interaction; concentration; then template and synchrony distributions. That sequence adds the strongest new evidence first without expanding beyond what Technocore actually exposes.
