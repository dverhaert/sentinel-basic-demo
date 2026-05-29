# Microsoft Sentinel — 1-Hour Hands-On Workshop

A short, hands-on Microsoft Sentinel demo for mixed SecOps audiences. Three exercises that build on each other: **triage → hunt → visualize**.

> **Audience:** Mixed SecOps — familiar with SIEM concepts, new to Sentinel
> **Duration:** ~1 hour (10 min intro, 3 × 15 min exercises, 5 min wrap)
> **Prereq:** Each participant needs reader/contributor access to a shared Sentinel workspace. Easiest setup: deploy the **Microsoft Sentinel Training Lab** solution from Content Hub — it seeds sample data so no real logs are required.

---

## Timing

| Block | Time | Activity |
|---|---|---|
| Intro & orientation | 10 min | What Sentinel is, tour of the workspace |
| Exercise 1 — Incident triage | 15 min | Investigate a pre-seeded incident |
| Exercise 2 — KQL hunting | 15 min | Write queries to find suspicious sign-ins |
| Exercise 3 — Workbook | 15 min | Pin findings into a dashboard |
| Wrap & Q&A | 5 min | Recap + where to go next |

---

## Repository contents

```
.
├── README.md                                 ← this file
├── workbook-starter.json                     ← importable workbook for Exercise 3
└── queries/
    ├── 01-failed-signins.kql                 ← Exercise 2 baseline
    ├── 02-impossible-travel.kql              ← Exercise 2 final query
    ├── 03-failed-signins-timechart.kql       ← Exercise 3 tile 1
    └── 04-signins-by-country.kql             ← Exercise 3 tile 2
```

All `.kql` files are copy-paste ready into **Sentinel → Logs**. The workbook JSON can be imported via **Workbooks → New → Advanced Editor → Gallery Template**.

---

## Intro (10 min)

Quick framing — keep it short, the group already knows SIEM:

- Sentinel = cloud-native SIEM + SOAR on Azure, no infrastructure to manage
- Three core surfaces:
  - **Logs** — KQL queries against ingested data
  - **Incidents** — triage and investigation
  - **Workbooks** — interactive dashboards
- The flow: **Data connectors → Analytics rules → Incidents → Investigation → Automation**
- Take a quick tour of the left-nav of a Sentinel workspace

---

## Exercise 1 — Triage a suspicious sign-in incident (15 min)

**Scenario:** An employee account triggered a high-severity alert overnight. Triage it.

**Tasks:**

1. Open **Incidents** → filter to **High** severity → pick the seeded *"Anomalous sign-in"* incident
2. Assign it to yourself, set status to **Active**
3. Open the **investigation graph** — identify the **user**, **IP**, and **device** entities
4. Answer: *Where did the sign-in originate? Is there a second sign-in from a different country within 1 hour?*
5. Add a **comment** with your verdict (true positive / false positive) and close the incident

**Discussion points:**
- Entity pivoting in the investigation graph
- MITRE ATT&CK tactic tagging on incidents
- How Sentinel auto-groups related alerts into a single incident

---

## Exercise 2 — Hunt with KQL (15 min)

**Scenario:** Use what you learned in Exercise 1 to hunt for the same pattern across the whole tenant.

**Step 1 — Baseline query**

Open **Logs** and run [`01-failed-signins.kql`](queries/01-failed-signins.kql):

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    DistinctIPs   = dcount(IPAddress),
    Countries     = make_set(tostring(LocationDetails.countryOrRegion), 10)
    by UserPrincipalName
| where FailedAttempts > 10
| sort by FailedAttempts desc
```

**Step 2 — Extend to impossible travel**

Now modify the query to find users signed in from **two different countries within 1 hour** — physically impossible. Hint: use `serialize` + `prev()` to compare each row to the prior row for the same user.

Reference solution: [`02-impossible-travel.kql`](queries/02-impossible-travel.kql)

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          Country = tostring(LocationDetails.countryOrRegion)
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated),
         PrevUser = prev(UserPrincipalName),
         PrevCountry = prev(Country)
| where UserPrincipalName == PrevUser
| where Country != PrevCountry
| where TimeGenerated - PrevTime < 1h
| project UserPrincipalName, PrevCountry, Country,
          PrevTime, TimeGenerated, TimeDelta = TimeGenerated - PrevTime
```

**Step 3 — Save as a hunting query**

In **Sentinel → Hunting → Queries → New Query**, paste the final query, give it a name and a MITRE tactic (Initial Access / Credential Access), and save.

**Discussion points:**
- KQL pipe model — each `|` transforms the table
- `summarize` vs `join` — when each makes sense
- The difference between a **hunting query** (ad-hoc) and an **analytics rule** (scheduled, generates incidents)

---

## Exercise 3 — Build a workbook tile (15 min)

**Scenario:** Surface what you hunted as a recurring dashboard for the SOC.

### Option A — Build from scratch

1. Go to **Workbooks → New → Add query**
2. Paste [`03-failed-signins-timechart.kql`](queries/03-failed-signins-timechart.kql), set visualization to **Time chart**
3. Add a second tile with [`04-signins-by-country.kql`](queries/04-signins-by-country.kql)
4. Switch its visualization to **Map** (pick `Country` as the location field) or **Bar chart**
5. Save the workbook as *"Identity Risk — Quick View"*

### Option B — Import the starter workbook

If you're short on time, import [`workbook-starter.json`](workbook-starter.json) directly:

1. **Workbooks → New** → click the **`</>` Advanced Editor** icon
2. Switch the template type to **Gallery Template**
3. Paste the contents of `workbook-starter.json` and click **Apply**
4. Click **Done Editing → Save**

**Discussion points:**
- Parameters (the time-range picker drives both tiles)
- How workbooks are JSON under the hood — easy to source-control
- Sharing workbooks across the SOC team

---

## Wrap up (5 min)

- Recap: you triaged an incident, hunted with KQL, and visualized findings — the full SecOps loop
- Next steps: analytics rule templates, UEBA, automation playbooks (Logic Apps)
- Resources:
  - [SC-200 learning path](https://learn.microsoft.com/training/courses/sc-200t00)
  - [Azure-Sentinel GitHub repo](https://github.com/Azure/Azure-Sentinel) — KQL query library, workbooks, playbooks
  - [KQL quick reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)