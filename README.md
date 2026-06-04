# Microsoft Sentinel — Basic Hands-On Lab

This lab walks through a simple Microsoft Sentinel workflow from end to end: **triage an incident, hunt with KQL, then turn the results into a workbook**.

It is written for people who already know basic SIEM concepts but are new to Microsoft Sentinel.

> **Prereq:** You need at least reader access to a Sentinel workspace that already contains sample sign-in data (contributor is only needed for optional sandbox save/create tasks).
<!-- > The easiest setup is the **Microsoft Sentinel Training Lab** solution from Content Hub. -->

> **Platform update (2026):** For new detections, Microsoft recommends **custom detection rules** in the Microsoft Defender portal as the primary path. Scheduled **analytics rules** are still available and useful in some scenarios, especially for Sentinel-ingested data. Also note the Azure portal Sentinel experience is on a retirement timeline, with Defender portal as the long-term destination.

> **Shared lab mode:** This guide is written for multi-user environments. By default, run the exercises in **read-only / no-save mode** so participants do not modify incidents, rules, or workbooks used by others.

---

## Before you start

Microsoft Sentinel is a cloud-native SIEM and SOAR platform in Azure. In this lab, you will use three core parts of the product:

- **Incidents** to investigate security alerts that were generated from detections
- **Logs** to query raw and normalized telemetry with Kusto Query Language (KQL)
- **Workbooks** to present findings in a reusable dashboard

The exercises follow a common SOC workflow:

1. Start with a suspicious incident
2. Pivot into the underlying telemetry
3. Search for the same pattern across the environment
4. Turn the result into a reusable dashboard view (or a draft in shared read-only mode)

If you are new to KQL, treat it as a pipeline language: each line takes the result from the previous line and transforms it. Common operators in this lab are:

- `where` to filter rows
- `project` to choose or rename columns
- `summarize` to aggregate results
- `sort by` to order the output
- `extend` to create calculated columns

---

## What you will do

- Investigate an existing incident in your environment
- Query `SigninLogs` to find repeated failures and suspicious travel patterns
- Build a simple workbook design that visualizes sign-in activity
- If you have extra time: design a custom detection and enrichment approach, and run a KQL job over long-term data

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

## Exercise 1 — Triage a suspicious incident (15 min)

**Scenario:** Pick a recent incident from your environment and triage it.

In Sentinel, an incident is the investigation container that pulls together related alerts, entities, and evidence. Your goal is to understand what happened, decide whether it is suspicious, and record a clear conclusion.

For shared environments, avoid changing incident ownership/state. Treat this as an investigation walkthrough and capture your verdict in your own notes.

**Tasks:**

1. Open **Incidents** → choose a recent incident with identity or sign-in context
*Please keep the incident unchanged (do not reassign owner, status, or classification) so other people can use the lab*
1. Open the **investigation graph** — identify the **user**, **IP**, and **device** entities
2. Answer: *Where did the activity originate? Is there evidence of a second sign-in from a different country within 1 hour?*
3. Record your verdict (true positive / false positive / needs more data) in personal notes instead of commenting on and closing the shared incident

---

## Exercise 2 — Hunt with KQL (15 min)

**Scenario:** Use what you learned in Exercise 1 to hunt for the same pattern across the whole tenant.

The `SigninLogs` table contains Microsoft Entra ID sign-in events. In this exercise, you will first find accounts with repeated failed sign-ins, then look for a stronger signal: successful sign-ins from different countries within a short period.

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

Now modify the query to find users signed in from **two different countries within 1 hour**. This pattern is often called impossible travel because the same user appears to move farther than physically possible in the time available. Hint: use `serialize` + `prev()` to compare each row to the prior row for the same user.

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

In **Sentinel → Hunting → Queries → New Query**, paste the final query, give it a name and a MITRE tactic (Initial Access / Credential Access), and save **only if you are working in an isolated personal lab**.

In shared environments, run the query and keep a local copy of the KQL instead of saving tenant-level artifacts.

A hunting query is useful for analyst-led exploration. If you later want automated alerts, the next step is to operationalize the logic as a **custom detection rule** (preferred) or a scheduled **analytics rule** when that is the better fit for your environment.

---

## Exercise 3 — Build a workbook tile (15 min)

**Scenario:** Surface what you hunted as a recurring dashboard for the SOC.

Workbooks are Sentinel dashboards built from queries, parameters, and visualizations. They are useful when you want to move from one-off analysis to something the team can reopen and use repeatedly.

### Option A — Build from scratch

1. Go to **Workbooks → New → Add query**
2. Paste [`03-failed-signins-timechart.kql`](queries/03-failed-signins-timechart.kql), set visualization to **Time chart**
3. Add a second tile with [`04-signins-by-country.kql`](queries/04-signins-by-country.kql)
4. Switch its visualization to **Map** (pick `Country` as the location field) or **Bar chart**
5. In shared environments, use **Done Editing** without saving, or save only to a personal workspace/resource group

### Option B — Import the starter workbook

If you want to start from a prepared template, import [`workbook-starter.json`](workbook-starter.json) directly:

1. **Workbooks → New** → click the **`</>` Advanced Editor** icon
2. Switch the template type to **Gallery Template**
3. Paste the contents of `workbook-starter.json` and click **Apply**
4. Review the tiles; save only in an isolated personal environment

---

## Bonus Exercise 4 — Turn the hunt into a custom detection and enrich incidents

**Scenario:** Your impossible-travel hunt looks useful enough to operationalize. Convert it into a detection rule and make sure new incidents are enriched automatically for analysts.

This exercise moves from ad-hoc hunting into repeatable detection engineering. The goal is to create a rule that generates alerts/incidents and apply lightweight automation so triage starts with more context.

For shared training tenants, treat this as a design exercise unless the instructor provides an isolated sandbox.

**Tasks:**

1. In the **Microsoft Defender portal**, open the detection authoring experience (for example, **Detection engineering / Manage rules**) and draft a **custom detection rule** configuration
2. Reuse the query from Exercise 2, or simplify it so it returns only the events you want to alert on
3. Name the rule *"Impossible Travel - Demo"* and configure execution settings that match your objective (for example, hourly)
4. Configure alert and incident behavior, including severity and key entity mapping (user, IP, location)
5. Save and enable the rule only in an isolated sandbox
6. Create or update an **automation rule** only in an isolated sandbox so incidents from this detection are enriched consistently
7. Add simple enrichment actions, such as assigning severity, adding a tag, updating the title, or adding a comment that tells the analyst this incident came from the impossible-travel detection
8. If enabled in a sandbox, trigger the rule on fresh data and confirm the resulting incident includes the enrichment you configured

If your tenant still uses the classic Sentinel analytics workflow, you can perform the same exercise with a scheduled analytics rule and equivalent enrichment automation.

This pattern is the bridge from hunting to operations: the detection rule creates the signal, and automation standardizes the first response steps.

---

## Bonus Exercise 5 — Run a KQL job over the data lake

**Scenario:** You want to analyze a larger time range than you would normally query interactively. Use a KQL job over the data lake to scan historical data and return the most relevant results.

Interactive queries are best for fast investigation over recent data. A KQL job is better when you need to search larger volumes or longer retention windows without waiting in the normal Logs experience.

**Tasks:**

1. Open the data lake or long-term search surface available in your Sentinel environment
2. Start with the impossible-travel logic from Exercise 2, then widen the time range to something larger such as 7 or 30 days
3. Reduce the output to the columns you actually need, for example `UserPrincipalName`, `Country`, `PrevCountry`, `TimeGenerated`, and `IPAddress`
4. Submit the query as a **KQL job** instead of running it interactively
5. When the job completes, review the output and identify the top users, countries, or source IPs involved in suspicious travel patterns
6. Save the job results or export the findings if your environment supports it
7. Decide whether the pattern should feed a new workbook tile, a hunting query, or a production custom detection rule (or analytics rule where applicable)

If your environment does not expose the data lake features, you can still do the exercise conceptually by widening the query window and discussing when you would choose a batch-style job instead of an interactive query.

---

## Wrap up

- Recap: you triaged an incident, hunted with KQL, and visualized findings — the full SecOps loop
- Next steps: in a personal sandbox, move from draft content to custom detection rules, UEBA, automation playbooks (Logic Apps), and longer-range hunts over historical data
- Resources:
  - [SC-200 learning path](https://learn.microsoft.com/training/courses/sc-200t00)
  - [Azure-Sentinel GitHub repo](https://github.com/Azure/Azure-Sentinel) — KQL query library, workbooks, playbooks
  - [KQL quick reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)