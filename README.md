# sentinel-basic-demo

Hands-on Microsoft Sentinel demo for a large Shell audience to explore incident investigation, KQL, and workbooks in a guided 1-2 hour session.

## Recommended format

- **Audience:** ~30 people
- **Duration:** 90 minutes (can be shortened to 60 minutes or stretched to 120 minutes)
- **Delivery:** 1 facilitator, optional 1-2 helpers for questions during hands-on sections
- **Mode:** Short demo blocks followed by guided exercises in Sentinel

## Learning goals

By the end of the session, participants should be able to:

1. Navigate the Sentinel portal and find incidents, alerts, entities, and evidence.
2. Run simple KQL queries and adjust filters and time ranges.
3. Use workbooks to review security trends and create a small workbook tweak.
4. Understand a basic investigation workflow from alert triage to escalation.

## Suggested session agenda

### Option A: 90-minute session

| Time | Topic | Outcome |
| --- | --- | --- |
| 0-10 min | Intro to Sentinel and session goals | Everyone understands the workflow for the session |
| 10-25 min | Facilitator demo: incidents and investigation graph | Participants see the end-to-end investigation flow |
| 25-45 min | Exercise 1: investigate an incident | Participants review incident severity, alerts, entities, and next actions |
| 45-65 min | Exercise 2: simple KQL queries | Participants run and adapt a few starter queries |
| 65-80 min | Exercise 3: workbooks | Participants use a workbook to answer a few monitoring questions |
| 80-90 min | Wrap-up and discussion | Capture findings, questions, and next steps |

### Option B: 120-minute session

Use the 90-minute agenda and add:

- 15 minutes for a deeper KQL exercise
- 15 minutes for a workbook customization exercise or team discussion

## Environment recommendations for a 30-person group

- Pre-load the Sentinel workspace with sample data and at least **3-5 realistic incidents**.
- Ensure all attendees have access before the session starts.
- Seat people in pairs if access is limited or if some attendees are new to Sentinel.
- Share a one-page cheat sheet with:
  - where to find incidents
  - how to change the time range
  - how to save or pin queries
  - common KQL operators (`where`, `project`, `summarize`, `sort by`, `take`)
- Have helpers available in the room or chat to unblock hands-on exercises quickly.

## Demo storyline

Use a simple storyline so the exercises feel connected:

> A suspicious sign-in pattern triggered an alert, produced an incident, and now the SOC analyst needs to understand scope, affected entities, and whether the activity should be escalated.

This storyline supports:

- incident triage
- entity investigation
- KQL hunting
- workbook review for trends and scope

## Exercise 1: incident investigation

### Goal

Review one incident and decide whether it should be closed, assigned, or escalated.

### Tasks

1. Open the incident queue and sort by severity.
2. Select the assigned demo incident.
3. Review:
   - incident title and severity
   - related alerts
   - impacted entities (user, host, IP)
   - MITRE tactics/techniques if available
   - comments, owner, and status
4. Open the investigation graph and identify:
   - the user involved
   - the source IP or device
   - the most suspicious indicator
5. Record a short conclusion:
   - what happened
   - what needs checking next
   - whether to escalate

### Debrief questions

- What made the incident suspicious?
- Which entity would you investigate first?
- What additional data would help you decide faster?

## Exercise 2: KQL basics

### Goal

Run simple queries and modify them to answer specific investigation questions.

### Starter queries

> Adjust the table names if your demo workspace uses different connectors.

#### Query 1: Recent incidents

```kusto
SecurityIncident
| where TimeGenerated > ago(7d)
| project TimeGenerated, Title, Severity, Status, Owner
| sort by TimeGenerated desc
```

#### Query 2: Alerts by severity

```kusto
SecurityAlert
| where TimeGenerated > ago(7d)
| summarize AlertCount = count() by AlertSeverity
| sort by AlertCount desc
```

#### Query 3: Sign-ins from a suspicious IP

```kusto
SigninLogs
| where TimeGenerated > ago(3d)
| where IPAddress == "10.10.10.10"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
| sort by TimeGenerated desc
```

### Participant challenges

Ask attendees to:

1. Change the time range from 7 days to 24 hours.
2. Filter results for one user or host.
3. Show only the columns they care about.
4. Count events by user, IP, or application.
5. Identify the top 5 results.

## Exercise 3: workbooks

### Goal

Use a workbook to answer simple operational questions and make a minor customization.

### Tasks

1. Open an existing Sentinel workbook.
2. Answer:
   - How many incidents were created this week?
   - Which severity appears most often?
   - Which analytic rule or data source is most visible?
3. Change one workbook setting:
   - time range
   - filter
   - visualization type
4. Optional: pin one result that would be useful for a SOC daily view.

## Facilitation notes

- Start with a short live demo before each exercise.
- Keep exercises tightly scoped so the room moves together.
- Use one "correct enough" answer per exercise to avoid long debates.
- If attendees have mixed experience levels, pair beginners with more technical users.
- Reserve the last 10 minutes for questions on real use cases at Shell.

## What success looks like

At the end of the session, attendees should have:

- opened and triaged at least one incident
- run and edited at least two KQL queries
- used a workbook to answer a basic monitoring question
- enough confidence to continue exploring Sentinel on their own
