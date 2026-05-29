# Microsoft Sentinel — Basic Hands-On Lab

This lab walks through a simple Microsoft Sentinel workflow from end to end: **triage an incident, hunt with KQL, then turn the results into a workbook**.

It is written for people who already know basic SIEM concepts but are new to Microsoft Sentinel.

> **Prereq:** You need reader or contributor access to a Sentinel workspace that already contains sample sign-in data. 
<!-- > The easiest setup is the **Microsoft Sentinel Training Lab** solution from Content Hub. -->

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
4. Save the result in a dashboard so the team can monitor it over time

If you are new to KQL, treat it as a pipeline language: each line takes the result from the previous line and transforms it. Common operators in this lab are:

- `where` to filter rows
- `project` to choose or rename columns
- `summarize` to aggregate results
- `sort by` to order the output
- `extend` to create calculated columns

---

## What you will do

- Investigate a seeded sign-in incident
- Query `SigninLogs` to find repeated failures and suspicious travel patterns
- Build a simple workbook that visualizes sign-in activity
- If you have extra time: create a custom detection, automate enrichment, and run a KQL job over long-term data

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

## Exercise 1 — Triage a suspicious sign-in incident (15 min)

**Scenario:** An employee account triggered a high-severity alert overnight. Triage it.

In Sentinel, an incident is the investigation container that pulls together related alerts, entities, and evidence. Your goal is to understand what happened, decide whether it is suspicious, and record a clear conclusion.

**Tasks:**

1. Open **Incidents** → filter to **High** severity → pick the seeded *"Anomalous sign-in"* incident
2. Assign it to yourself, set status to **Active**
3. Open the **investigation graph** — identify the **user**, **IP**, and **device** entities
4. Answer: *Where did the sign-in originate? Is there a second sign-in from a different country within 1 hour?*
5. Add a **comment** with your verdict (true positive / false positive) and close the incident

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

In **Sentinel → Hunting → Queries → New Query**, paste the final query, give it a name and a MITRE tactic (Initial Access / Credential Access), and save.

A hunting query is useful for analyst-led exploration. If you later want Sentinel to run the logic on a schedule and generate alerts automatically, the next step would be to turn the logic into an analytics rule.

---

## Exercise 3 — Build a workbook tile (15 min)

**Scenario:** Surface what you hunted as a recurring dashboard for the SOC.

Workbooks are Sentinel dashboards built from queries, parameters, and visualizations. They are useful when you want to move from one-off analysis to something the team can reopen and use repeatedly.

### Option A — Build from scratch

1. Go to **Workbooks → New → Add query**
2. Paste [`03-failed-signins-timechart.kql`](queries/03-failed-signins-timechart.kql), set visualization to **Time chart**
3. Add a second tile with [`04-signins-by-country.kql`](queries/04-signins-by-country.kql)
4. Switch its visualization to **Map** (pick `Country` as the location field) or **Bar chart**
5. Save the workbook as *"Identity Risk — Quick View"*

### Option B — Import the starter workbook

If you want to start from a prepared template, import [`workbook-starter.json`](workbook-starter.json) directly:

1. **Workbooks → New** → click the **`</>` Advanced Editor** icon
2. Switch the template type to **Gallery Template**
3. Paste the contents of `workbook-starter.json` and click **Apply**
4. Click **Done Editing → Save**

---

## Bonus Exercise 4 — Turn the hunt into a detection and enrich incidents

**Scenario:** Your impossible-travel hunt looks useful enough to operationalize. Convert it into a scheduled detection and make sure new incidents are enriched automatically for analysts.

This exercise moves from ad-hoc hunting into repeatable detection engineering. The goal is to create a rule that generates incidents, map it to the relevant MITRE ATT&CK technique or tactic, and apply lightweight automation so triage starts with more context.

**Tasks:**

1. Go to **Sentinel → Analytics → Create → Scheduled query rule**
2. Reuse the query from Exercise 2, or simplify it if needed so it returns only the events you want to alert on
3. Name the rule *"Impossible Travel - Demo"* and set a reasonable schedule such as every 1 hour over the last 24 hours
4. Configure the rule to create an incident and map the query to the appropriate MITRE ATT&CK category, such as **Initial Access** or **Credential Access**, based on how you want to describe the scenario
5. Save and enable the rule
6. Open the rule details and review how it appears in the **MITRE ATT&CK** view so you can see the detection represented in the matrix
7. Go to **Sentinel → Automation** and create an **automation rule** that runs when incidents are created from this analytics rule
8. Add simple enrichment actions, such as assigning severity, adding a tag, updating the title, or adding a comment that tells the analyst this incident came from the impossible-travel detection
9. Trigger the rule on fresh data if available, then confirm the resulting incident includes the enrichment you configured

This pattern is the bridge from hunting to operations: the analytics rule creates the signal, and the automation rule standardizes the first response steps.

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
7. Decide whether the pattern should feed a new workbook tile, a hunting query, or a production analytics rule

If your environment does not expose the data lake features, you can still do the exercise conceptually by widening the query window and discussing when you would choose a batch-style job instead of an interactive query.

---

## Wrap up

- Recap: you triaged an incident, hunted with KQL, and visualized findings — the full SecOps loop
- Next steps: analytics rule templates, UEBA, automation playbooks (Logic Apps), and longer-range hunts over historical data
- Resources:
  - [SC-200 learning path](https://learn.microsoft.com/training/courses/sc-200t00)
  - [Azure-Sentinel GitHub repo](https://github.com/Azure/Azure-Sentinel) — KQL query library, workbooks, playbooks
  - [KQL quick reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)