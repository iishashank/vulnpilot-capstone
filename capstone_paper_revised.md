# 1. TITLE

**An Autonomous Multi-Agent System for Automated Cybersecurity Reconnaissance and Vulnerability Scanning**

# 2. ABSTRACT

Vulnerability assessment is still often performed as a periodic exercise, even though the environments being assessed no longer change periodically. Public-facing infrastructure expands and contracts, service configurations shift, temporary assets appear outside formal change control, and exposed software states can differ materially between two scheduled scans. In such settings, a single scan result is useful but incomplete: it shows what was observed once, not what changed and why that change matters. This paper presents a capstone-scale autonomous multi-agent system for continuous cybersecurity reconnaissance and vulnerability scanning, designed to move from isolated scan output toward change-aware security posture monitoring.

The proposed system decomposes the monitoring workflow into cooperating technical agents for asset discovery, port and service enumeration, vulnerability intelligence correlation using CVE/NVD/CPE data, drift analysis across scan snapshots, and reporting and alert generation. Rather than using the word *agent* as a stylistic label, the system treats each agent as a bounded processing module with explicit inputs, outputs, and stored artifacts. The most important feature of the architecture is a drift analysis engine that compares current and previous scan states to identify newly exposed assets, changes in service exposure, newly matched vulnerabilities, and escalation events that warrant analyst attention. This shifts the focus from repeated vulnerability listing to meaningful security change detection.

The contribution of the work is therefore integrative and operational rather than algorithmically radical. It shows that a serious capstone implementation can combine continuous monitoring, structured orchestration, historical state comparison, and evidence-backed reporting into a coherent cybersecurity system. The resulting design is practical, extensible, and well suited to further research on autonomous security monitoring.

# 3. KEYWORDS

Autonomous cybersecurity; multi-agent systems; vulnerability scanning; continuous reconnaissance; attack surface monitoring; drift analysis; CVE correlation; explainable security reporting

# 4. INTRODUCTION

Security exposure is increasingly shaped by change. A web application that was correctly configured last week may now expose a new service. A test asset may be reachable for only a short period. A containerized workload may be replaced with another version between maintenance windows. In cloud and hybrid environments, the attack surface is not simply large; it is unstable. For defenders, this creates a practical difficulty: the inventory of what exists, what is reachable, and what is vulnerable may shift faster than conventional assessment practices are able to capture [1], [6], [10].

This matters because vulnerability management still relies heavily on periodic scanning and manual review. Those practices remain useful, but they assume a pace of infrastructure change that is increasingly unrealistic. A scheduled scan can tell an analyst what was exposed at the time it ran. It does not, by itself, say whether the exposure is newly introduced, whether a host has appeared unexpectedly, or whether a vulnerability is newly relevant because a service version changed since the prior run. In dynamic environments, that missing temporal context is often what determines urgency.

The problem is compounded by analyst workload. Mature scanners can return large, repetitive finding sets, many of which are already known. When each scan is presented mainly as another list of vulnerabilities, analysts spend time rediscovering the same issues and comparatively less time identifying what has actually changed. In practice, the operationally important question is often not only *what is vulnerable*, but *what changed in the security posture since the last observation*. That distinction is especially important in continuous monitoring, external attack surface management, and triage workflows where novelty and change frequently matter more than cumulative issue count [5], [6], [12].

These constraints motivate a more structured and autonomous approach. A multi-agent design is appropriate here because the workflow naturally breaks into distinct technical functions. Asset discovery is not the same problem as service enumeration. Vulnerability correlation requires different logic again, relying on external intelligence sources such as CVE, NVD, and CPE [2]–[4]. Historical comparison introduces a temporal dimension that does not belong inside the scanner itself. Reporting and alerting require a different output model oriented toward analysts rather than network tooling. Treating these concerns as separate agents is therefore a systems-engineering decision: each agent owns a specialized task, consumes typed inputs, emits typed outputs, and can be improved without destabilizing the rest of the pipeline [8], [9].

Within that broader design, scan-state comparison emerges as the most important architectural idea. Security monitoring is more useful when it can tell the analyst that a new host has appeared, a port has opened, or a previously unseen vulnerability has become relevant. These are not abstract differences. They are concrete posture changes that may indicate operational drift, unmanaged exposure, or newly introduced risk. A framework that persists scan snapshots and compares them over time offers a more practical monitoring model than one that treats every run as an isolated event.

This paper presents an autonomous multi-agent system for automated cybersecurity reconnaissance and vulnerability scanning, developed as a final-year engineering capstone project. The system organizes monitoring into agents for asset discovery, service and port scanning, vulnerability intelligence correlation, drift analysis, and reporting. The implementation is intentionally grounded: it uses a Python-based backend, a scheduler for recurring execution, persisted scan state, and a dashboard for analyst interaction. The emphasis is not on claiming a novel scanning primitive, but on building a coherent monitoring system that is technically credible, feasible for a capstone team, and strong enough to support research-oriented discussion.

The main contributions of the paper are summarized below.

- A modular multi-agent architecture in which each stage of the monitoring workflow has a clear technical role, explicit data contract, and persistent output.
- An automated recon-to-scan-to-correlation pipeline that links asset discovery, service enumeration, and vulnerability intelligence mapping using CVE/NVD/CPE data.
- A drift-aware comparison mechanism that treats historical scan-state change as a first-class security signal rather than an afterthought.
- An evidence-backed reporting and alerting model designed to reduce ambiguity and make automated outputs more interpretable to analysts.

# 5. RELATED WORK / LITERATURE REVIEW

## 5.1 Traditional Vulnerability Scanners and Their Limits

Traditional scanning tools such as Nmap, Nessus, and OpenVAS remain foundational in practical security work because they solve core problems reliably: host discovery, port enumeration, service detection, and vulnerability identification [1], [5]. They are effective precisely because they are not speculative; they encode established scanning methods and produce reproducible outputs. For that reason, any research paper in this area must be careful not to imply that scanning itself is the contribution.

Where these tools become less satisfactory is in how their outputs are operationalized over time. Most produce strong scan results, but many workflows around them still remain scan-centric rather than state-centric. Historical tracking exists in some commercial platforms, yet in many operational settings the analyst still interacts mainly with the latest result set and a familiar backlog of repeated findings. Compared with the proposed work, the gap is not raw detection capability; it is the absence of a lightweight, explicit mechanism that treats inter-scan change as a primary analytical object.

## 5.2 Attack Surface Discovery and External Exposure Monitoring

Work on attack surface discovery and external asset management begins from a different problem: organizations frequently do not know the full set of systems they are exposing [10], [11]. This literature is particularly relevant because it highlights that exposure risk cannot be reduced to software defects alone. New domains, forgotten subdomains, transient services, and externally reachable cloud assets all widen the attack surface independently of patch state.

Compared with classical vulnerability scanning, attack surface management is stronger on *what exists* but often weaker on *how the discovered surface is translated into vulnerability-specific and change-aware monitoring*. Many discovery-focused systems are inventory rich yet do not tightly couple discovery outputs with service-level intelligence correlation and structured temporal drift analysis. The proposed system is positioned between these two traditions: it uses continuous reconnaissance as the front door of the pipeline, but it does not stop at inventory. It pushes those results forward into scanning, correlation, comparison, and alerting.

## 5.3 Autonomous and Agent-Based Cybersecurity Systems

Agent-based cybersecurity research has examined how specialized autonomous components can sense, reason, and respond within complex cyber environments [8], [9]. In some of that work, agents are treated as semi-independent cyber-defense entities capable of local decision-making, adaptation, and coordination. That literature is conceptually useful, but much of it is either high-level, defense-oriented, or focused on adversarial response rather than monitoring-oriented exposure assessment.

The present work borrows the useful part of that tradition without overextending it. Here, “multi-agent” does not mean free-form autonomous intelligence. It means that the system is decomposed into bounded, cooperating task modules with explicit responsibilities and artifacts. This is a narrower and more defensible claim. Relative to the broader agent literature, the contribution is modest but concrete: the paper shows how an agent-oriented architecture can be applied to a practical cybersecurity monitoring pipeline in a way that is implementable by a capstone team and analytically useful.

## 5.4 Vulnerability Intelligence Correlation and Prioritization

Public vulnerability intelligence sources such as CVE, NVD, and CPE provide the structured backbone for correlation-based scanning systems [2]–[4]. Additional work on severity and prioritization, including CVSS and exploitability-oriented triage, has helped shape how scanning results are interpreted [7], [12], [13]. These bodies of work are essential to the present system because the quality of the reporting pipeline depends on the quality of the underlying intelligence mapping.

At the same time, prior work also makes clear that correlation is never perfect. Service fingerprints can be ambiguous. Product normalization is error-prone. Severity scores do not capture deployment context. Some systems respond by favoring breadth over interpretability, producing results at scale but with limited explanation. In contrast, the approach in this paper is narrower and more conservative: it prioritizes evidence-backed correlation over aggressive claims. In comparative terms, the distinguishing feature is not richer vulnerability intelligence than prior systems, but tighter coupling between correlation output, historical comparison, and explainable reporting.

## 5.5 Explainability in Security Tooling

The growing literature on explainable AI and interpretable decision support is relevant here because security practitioners need more than alerts; they need reasons [14]–[16]. In cybersecurity settings, trust is shaped less by polished presentation and more by traceability. A system is easier to trust when it can show which service was observed, how that service was normalized, which identifier was matched, and why a specific change was elevated.

Compared with many existing security dashboards, the proposed system places more emphasis on explainability at the reporting layer. This does not make the system unique in a broad sense, but it does address a recurring weakness in automated security tooling: alerts that surface without enough evidentiary context to support fast analyst judgment.

## 5.6 Comparative Gap

Taken together, the literature suggests a pattern. Traditional scanners are strong at detection but often weak at temporal interpretation. Attack surface discovery systems improve visibility but do not always connect discovery to vulnerability-specific and change-specific outputs. Agent-based security research provides an appealing architectural vocabulary but is often too broad or abstract for practical capstone-scale monitoring systems. Vulnerability intelligence sources are mature, but mapping and prioritization remain imperfect. Explainability is widely acknowledged as important, yet is still inconsistently implemented in operational tools.

The gap addressed by this work is therefore not the absence of scanning, discovery, or intelligence sources in isolation. It is the relative lack of lightweight systems that integrate these elements into a continuous, historical, and change-aware monitoring loop. The proposed system is best understood as an attempt to close that gap in a technically realistic way.

# 6. PROBLEM STATEMENT

Organizations do not simply need to know which vulnerabilities exist; they need to know when their exposure changes. Existing vulnerability management practices often rely on periodic scans, manual review, and repeated inspection of largely static issue lists. In dynamic environments, that model is insufficient because security-relevant change can occur between scan windows and may remain hidden until the next scheduled assessment.

This project addresses the practical need for a continuous, autonomous monitoring system that can discover assets within an authorized scope, enumerate exposed services, correlate observations with known vulnerability intelligence, preserve scan state across time, and identify meaningful changes between scan snapshots. The system is intended to fill the gap between one-time scanning and continuous security posture awareness by producing not only findings, but also interpretable change events.

# 7. RESEARCH OBJECTIVES

1. **To automate asset discovery within an authorized monitoring scope.**  
   The system should identify reachable assets without requiring repeated manual host enumeration.

2. **To perform structured port and service scanning.**  
   The framework should capture exposed services and ports in a form suitable for downstream processing.

3. **To correlate observed services with public vulnerability intelligence.**  
   The system should map service evidence to CVE/NVD/CPE data and preserve supporting evidence for each inferred finding.

4. **To coordinate monitoring stages through a modular multi-agent architecture.**  
   Each stage should function as a bounded technical component with explicit inputs, outputs, and dependencies.

5. **To detect drift between scan states.**  
   The system should identify changes such as new assets, removed assets, changed services, and newly matched vulnerabilities.

6. **To generate explainable alerts and reports.**  
   The output should prioritize clarity, evidence, and analyst usability rather than raw volume alone.

7. **To remain practical for capstone-scale development and deployment.**  
   The implementation should be achievable with accessible tools and a manageable engineering scope.

# 8. NOVELTY / RESEARCH GAP / CONTRIBUTION POSITIONING

The contribution of this work should be framed carefully. The paper does not claim to introduce a new theory of network scanning, a new vulnerability database, or a new prioritization standard. Those components already exist and are well established in the literature and in practice [1]–[5], [7].

What this work contributes is a specific integration strategy. It combines continuous reconnaissance, explicit agent-based orchestration, vulnerability intelligence correlation, persisted scan snapshots, and differential posture analysis into a single autonomous monitoring system. The value of the system lies less in any one stage than in the way those stages reinforce one another. Discovery becomes more useful when it feeds structured scanning. Scanning becomes more useful when it is enriched with public intelligence. Findings become more useful when they are interpreted against prior state rather than read in isolation.

The strongest and most defensible point of novelty is the treatment of **drift-aware monitoring** as a primary design concern. Many systems can tell an analyst what is present. Fewer systems, especially at lightweight prototype scale, are built around the question of what changed and whether that change is security-relevant. In that sense, the work is not novel because it scans; it is novel in the more modest sense that it reorganizes familiar techniques into a historically aware and operationally focused monitoring framework.

This is a useful distinction. It avoids overclaiming while still showing why the project is worth doing. In dynamic environments, a system that highlights newly introduced exposure may be more operationally valuable than one that simply produces another full inventory of known issues.

# 9. SYSTEM OVERVIEW

## 9.1 End-to-End Workflow

The system begins when an analyst defines an authorized target scope, such as a domain, subnet, or managed site profile. That scope is stored with policy and scheduling metadata so that monitoring is repeatable and bounded. Once a scan is triggered, either manually or by schedule, the orchestration layer creates a run context and passes it into the processing pipeline.

The Asset Discovery Agent first identifies reachable assets within the scope. These may be hostnames, IP addresses, or other concrete network endpoints. The Scan Agent then enumerates ports and services for the discovered assets and records the resulting service fingerprints. The Vulnerability Intelligence Agent consumes those fingerprints and attempts to map them to normalized product identifiers and known vulnerability records using sources such as CVE, NVD, and CPE.

After the current scan state is stored, the Drift Analysis Agent compares it against a previous state associated with the same scope. This comparison produces structured change events: new assets, removed assets, changed service exposure, and newly observed or escalated vulnerabilities. Finally, the Reporting and Alerting Agent turns those outputs into prioritized findings, alerts, and dashboard-visible summaries.

This workflow matters because it shifts the system from “scan and display” toward “observe, compare, and explain.” The scan result remains important, but it is no longer the only product of the run.

## 9.2 Design Philosophy

Five design principles shape the system.

The first is **modularity**. Each agent handles one stage of the pipeline and produces structured artifacts for the next stage.

The second is **automation with boundaries**. The system is designed to reduce routine manual effort, but it does so within clearly defined scope, policy, and scheduling controls.

The third is **historical awareness**. Scan output is stored because the system is designed to compare states, not merely to display the latest one.

The fourth is **evidence preservation**. Findings and alerts should be explainable in terms of observed services, matched intelligence, and detected change.

The fifth is **capstone feasibility**. The architecture must be realistic for a student engineering team while still being strong enough to support research-style analysis and extension.

# 10. SYSTEM ARCHITECTURE

## 10.1 Overall Architecture

The proposed system follows a layered architecture consisting of a presentation layer, an orchestration layer, and a data layer. This is not only a software organization choice; it reflects the separation between analyst interaction, autonomous monitoring logic, and persisted state. The presentation layer handles interaction and visualization. The orchestration layer sequences monitoring tasks and manages agent execution. The data layer stores both operational records and vulnerability intelligence.

This structure supports a useful property: the same stored scan state can be consumed by both the dashboard and the drift engine. In other words, persistence is not merely archival. It is part of the computational model.

## 10.2 Presentation Layer

The presentation layer provides analyst access to scope configuration, scan lifecycle monitoring, findings review, alert inspection, and historical comparison. In the capstone implementation, a web-based dashboard is the most practical choice because it supports visualization, tabular output, and interactive control without introducing the additional overhead of native client development.

The dashboard is not meant to be a cosmetic layer over command-line tools. It is intended to expose the system’s internal state in a usable way: active runs, discovered assets, correlated findings, drift outputs, and alert acknowledgment workflows. Although the broader architecture could later support other clients through the same service layer, the current system should be described accurately as a web-first monitoring prototype.

## 10.3 Backend / Orchestration Layer

The orchestration layer is the operational core of the system. It manages scope registration, scan-run creation, scheduling, agent sequencing, and API exposure. It is responsible for ensuring that outputs from one stage are persisted and made available to the next stage, rather than being lost as transient scanner text.

In practical terms, this layer exposes endpoints for creating and listing monitored scopes, starting scans, checking run status, retrieving assets and findings, acknowledging alerts, and comparing recent scan states. It also controls scheduling and background execution so that monitoring can occur repeatedly without blocking analyst interaction.

## 10.4 Data Layer

The data layer contains two kinds of information. The first is application state: sites, scan runs, logs, assets, findings, alerts, and workflow metadata. The second is threat intelligence: locally indexed CVE, CPE, and related vulnerability data used for correlation.

This separation matters because the two datasets evolve differently. Application state changes with every scan. Threat intelligence changes more slowly and is reused across many runs. Keeping them conceptually distinct helps maintain clean interfaces and simplifies optimization decisions later.

## 10.5 Agent Interaction Model

The agent interaction model is pipeline-oriented, but not merely sequential in a superficial sense. Each agent is responsible for transforming one specific representation into another:

- scope into asset candidates,
- asset candidates into service observations,
- service observations into vulnerability records,
- current and prior records into drift events,
- drift events and findings into analyst-facing outputs.

This gives the multi-agent framing technical substance. The agents are not decorative names attached to one monolithic script. They are functional boundaries in the dataflow. Each can be tested, replaced, or improved independently as long as the input and output contracts are preserved.

## 10.6 Scheduler / Continuous Scan Control

Continuous monitoring depends on recurring execution. The scheduler therefore acts as the control mechanism that moves the system from manual scanning toward ongoing observation. Managed scopes can be configured for manual or periodic execution, and each execution creates a new scan state that becomes part of the historical record.

A mature deployment would require durable scheduling semantics, persistence across restarts, failure recovery, and better concurrency control. Those are important engineering concerns. Still, even in prototype form, the scheduler establishes the key research property of the system: repeat observation over time.

## 10.7 Security and Authorization Controls

Authorization is a core design constraint rather than a UI reminder. Because the system is capable of network reconnaissance and scanning, scope ownership or permission must be recorded and enforced consistently. The architecture is therefore built around managed scopes and explicit authorization confirmation.

From a systems perspective, this is important because policy must live in the backend, not only in interface text. A continuous monitoring platform that automates scan execution must be especially careful about scope control. This is both an engineering requirement and an ethical one.

[Figure 1: High-Level System Architecture Placeholder  
Description: A layered architecture diagram showing Security Analyst/User -> Dashboard/UI -> Backend Orchestrator -> Agent Modules (Recon Agent, Scan Agent, Vulnerability Intelligence Agent, Drift Analysis Agent, Alerting Agent) -> Databases (Application DB, Threat Intelligence DB). Include arrows for control flow and data flow.]

Figure 1 should depict the system as a control-and-data pipeline rather than a flat collection of components. The user interface should appear at the top as the point of interaction, with the backend orchestrator directly beneath it. The agent modules should sit in the processing layer, each represented as a distinct function in the monitoring chain. At the bottom, the diagram should show separate stores for operational data and vulnerability intelligence.

The figure should also distinguish the type of exchange taking place. Control flow arrows should show when a user action or scheduler event initiates a run. Data flow arrows should show how assets, findings, drift outputs, and alerts move through the system and into persistent storage.

# 11. AGENT DESIGN AND RESPONSIBILITIES

## 11.1 Asset Discovery Agent

The Asset Discovery Agent identifies reachable assets within an authorized target scope. Its input is a bounded scope definition together with policy constraints that govern how discovery should be performed. Its output is a normalized asset set containing identifiers such as hostnames, IP addresses, reachability information, and discovery timestamps.

Internally, this agent can combine conservative discovery logic such as DNS resolution, host validation, and bounded probing. The exact technique may vary by environment, but the engineering objective remains stable: turn a broad scope definition into a concrete and reviewable set of candidate assets.

The agent passes those candidates to the Scan Agent. Its implementation is well within capstone scope because it can be built incrementally, starting from modest discovery logic and improving over time.

## 11.2 Scan Agent

The Scan Agent enumerates ports and services on the assets identified by discovery. It receives an asset list and a scan profile, then produces structured records describing open ports, observed services, protocol information, and version indicators where available.

Its internal logic is typically built around established scanning tools such as Nmap [1]. The important engineering decision is to parse and persist the output as structured data instead of treating it as terminal text. This makes the results usable for downstream intelligence correlation and historical comparison.

The Scan Agent depends on the Asset Discovery Agent and feeds the Vulnerability Intelligence Agent. Its role is narrow, essential, and technically well defined.

## 11.3 Vulnerability Intelligence Agent

The Vulnerability Intelligence Agent enriches observed service information with vulnerability context. Its inputs include service names, version strings, banners, and other fingerprinting evidence. Its outputs are structured findings linked to known vulnerability identifiers and associated metadata.

Internally, the agent performs normalization, identifier mapping, and lookup operations. A service fingerprint is interpreted into a likely product and version, then translated into a CPE-like form where possible, and finally matched against CVE/NVD records [2]–[4]. The agent also attaches supporting evidence, descriptive text, severity metadata, and, where appropriate, remediation guidance.

This agent is particularly important because it sits at the boundary between measurement and interpretation. It does not merely repeat vulnerability database entries; it attempts to justify why a specific entry is relevant to an observed service.

## 11.4 Drift Analysis Agent

The Drift Analysis Agent compares the current scan state against a prior state for the same monitored scope. Its input is not scanner output alone, but persisted historical state. Its output is a set of structured drift events describing how exposure has changed.

Internally, the agent performs keyed comparison over assets, ports, services, and vulnerability records. It identifies newly observed assets, removed assets, changed exposure, new findings, resolved findings, and escalation cases. This agent is the stage that turns repeated scanning into monitoring.

Its interaction with the rest of the system is significant. It depends on persistence from earlier stages, and the Reporting and Alerting Agent depends directly on its output. In research terms, this is where the system moves beyond a conventional periodic scanner.

## 11.5 Reporting and Alerting Agent

The Reporting and Alerting Agent transforms current findings and drift outputs into analyst-facing artifacts. It receives structured evidence, severity metadata, and differential events, then produces alerts, summaries, and report-ready views suitable for operational interpretation.

Internally, this agent prioritizes change events and assembles explainable records. For example, a newly opened service on an exposed asset may be more important than a low-priority historical finding that has been present for weeks. The agent therefore acts as a bridge between technical monitoring output and analyst decision support.

Its implementation is feasible because it operates on already structured data. The challenge is not tooling complexity so much as reporting discipline: the outputs need to stay grounded in evidence and historical context.

## 11.6 Agent Responsibility Table

**Table 1: Agent Responsibilities, Inputs, Outputs, and Dependencies**

| Agent | Primary Responsibility | Inputs | Outputs | Key Dependencies |
|---|---|---|---|---|
| Asset Discovery Agent | Identify reachable assets within authorized scope | Domain, IP range, policy, schedule context | Asset list, host metadata, discovery timestamps | Scope registry, network visibility |
| Scan Agent | Enumerate ports and services on discovered assets | Asset list, scan profile | Open ports, service banners, version fingerprints | Discovery output, scan tools such as Nmap |
| Vulnerability Intelligence Agent | Map observed services to known vulnerabilities | Service fingerprints, product/version candidates | CVE/CPE-linked findings, severity metadata, evidence | Local vulnerability database, NVD/CVE/CPE sources |
| Drift Analysis Agent | Compare current and prior scan snapshots | Current snapshot, prior snapshot(s) | New assets, removed assets, changed ports, new or escalated findings | Persisted scan state, normalized asset/finding model |
| Reporting and Alerting Agent | Produce explainable alerts and analyst-facing summaries | Findings, severity context, drift events, evidence | Alerts, dashboard summaries, reports, triage cues | UI/API layer, alert policy, reporting templates |

# 12. METHODOLOGY

The methodology follows the actual logic of the proposed monitoring system: a scope is defined, assets are discovered, services are enumerated, observations are correlated with vulnerability intelligence, the resulting state is stored, and historical comparison is performed before alerts are surfaced. Each stage produces a concrete intermediate artifact, which is important both for engineering clarity and for later evaluation.

## 12.1 Stage 1: Target Scope Initialization

The process begins with the creation of a managed scope. This stage exists to define what the system is permitted to monitor and how often that monitoring should occur. Inputs include the target domain, IP range, authorization confirmation, and the desired scan policy or cadence. The output is a normalized scope record and an associated run context.

This stage is operationally modest but architecturally important. A monitoring system that does not clearly separate authorized scope management from raw scan execution risks both technical ambiguity and policy failure.

## 12.2 Stage 2: Asset Discovery

Once a scope is established, the system performs discovery to determine which assets are currently visible. The aim is not broad internet-scale reconnaissance, but bounded discovery within the authorized monitoring region. Inputs include the managed scope and policy settings. Outputs include a list of discovered assets with host-level metadata.

The discovery stage provides the substrate for everything that follows. If the asset set is incomplete, the later stages inherit that incompleteness. For that reason, discovery results are stored as part of the scan snapshot and not discarded after scanning.

## 12.3 Stage 3: Port and Service Enumeration

The third stage enriches discovered assets with service exposure details. Each asset is examined for open ports, reachable services, and, where possible, product or version indicators. Inputs are the discovered assets and the selected scan profile. Outputs are structured service fingerprints associated with specific assets.

This stage is where raw network exposure begins to acquire security meaning. Open ports and service versions are not final findings, but they are the evidence from which later findings are inferred.

## 12.4 Stage 4: Vulnerability Correlation

At this stage, service evidence is matched against known vulnerability intelligence. The purpose is not to guess aggressively, but to derive justified findings from observed data. Inputs include fingerprints, normalized product candidates, and a local or cached vulnerability intelligence store. Outputs are finding records that preserve both the matched identifier and the evidence chain.

This stage links directly to the next because the drift engine needs more than current network state. It also needs current vulnerability state.

## 12.5 Stage 5: Drift / Differential Analysis

The fifth stage compares the newly generated scan snapshot against a previous one for the same scope. It is here that the methodology departs most clearly from a standard scan-run model. The comparison is performed over structured state representations of assets, services, and findings rather than over unstructured scan logs.

The output is a set of drift events that capture meaningful change. These events become the basis for prioritization and alerting.

## 12.6 Stage 6: Alert Generation and Reporting

The final stage transforms technical artifacts into analyst-facing output. Inputs include current findings, differential events, severity information, and supporting evidence. Outputs include alert records, dashboard summaries, and report views.

This stage completes the system’s methodological shift from measurement to interpretation. The underlying data remains technical, but the output is structured for decision support.

[Figure 2: End-to-End Processing Pipeline Flowchart Placeholder  
Description: A flowchart beginning with Target Input -> Asset Discovery -> Host Validation -> Nmap Scan -> Service Version Detection -> CPE/CVE Correlation -> Snapshot Storage -> Drift Comparison -> Severity Prioritization -> Alert Generation -> Dashboard/API Output.]

Figure 2 should show that snapshot storage is not an afterthought inserted at the end of the pipeline. It is a central step that makes later comparison possible. The flowchart should also make the analyst-facing steps visually downstream of the technical processing stages, reinforcing the idea that alerts and reports are derived products of persisted monitoring state.

# 13. DRIFT ANALYSIS / DIFFERENTIAL SECURITY POSTURE ENGINE

If the system described in this paper has one clear intellectual center, it is the drift analysis engine. Scanning itself is established. Vulnerability correlation is difficult but familiar. What gives this project its strongest research character is the attempt to formalize *security posture change* as a persistent, queryable output rather than as a human inference made informally between two scanner screens.

A single scan snapshot says, in effect, “this is what was seen.” That is useful, but it leaves an important gap. In real environments, risk is often introduced by change: a new host becomes reachable, a development service appears in production, an additional port is exposed, a version shift makes a prior mapping newly relevant, or a previously unknown asset enters the monitored surface. None of these cases is well represented by a system that simply produces a fresh vulnerability list every time it runs.

The drift engine addresses this by treating each run as a state transition. Let \( S_t \) denote the scan state at time \( t \). Each state may be represented through three principal sets:

- \( A_t \): the asset set observed at time \( t \)
- \( P_t \): the port and service exposure set at time \( t \)
- \( V_t \): the vulnerability finding set at time \( t \)

This decomposition is helpful because different kinds of drift occur in different layers of the observed system. Asset-level drift and vulnerability-level drift are related, but not identical. A new asset may appear before any vulnerability is matched. A vulnerability may appear because a version changed even when the asset itself did not.

Using this notation, several important change categories can be expressed directly.

\[
\text{NewAssets}_t = A_t \setminus A_{t-1}
\]

\[
\text{RemovedAssets}_t = A_{t-1} \setminus A_t
\]

\[
\text{NewVulnerabilities}_t = V_t \setminus V_{t-1}
\]

\[
\text{ResolvedVulnerabilities}_t = V_{t-1} \setminus V_t
\]

For a shared asset \( a \in A_t \cap A_{t-1} \), service or port drift is identified by comparing its associated service state:

\[
\Delta P(a) = P_t(a) \neq P_{t-1}(a)
\]

This captures situations such as a newly open port, a closed service, or a service version change. In implementation terms, these are not abstract equations so much as a disciplined way of structuring keyed comparisons.

Vulnerability escalation can also be represented at the record level. For a finding \( v \in V_t \cap V_{t-1} \), the system may emit an escalation event if the relevant priority state increases between snapshots:

\[
\text{Escalation}(v) =
\begin{cases}
1, & \text{if severity increases between } t-1 \text{ and } t \\
1, & \text{if exploitability context becomes more critical} \\
0, & \text{otherwise}
\end{cases}
\]

The practical value of this model is not mathematical elegance. It is that it helps the system answer more useful questions. Did a host appear? Did exposure expand? Did a finding become newly relevant? Did a previously open service disappear? These are questions analysts routinely care about, yet many scanning workflows answer them only indirectly, if at all.

In engineering terms, the drift engine can be implemented with modest complexity using indexed maps keyed by host, service, and finding identifiers. That keeps the comparison logic understandable and makes it realistic for a capstone implementation. The resulting output is a set of structured change events rather than a prose summary assembled after the fact. That design choice is significant because it allows downstream alerting logic to reason over explicit event types.

The engine is also central to explainability. A drift event can point to two concrete states and a precise difference between them. That is far more actionable than a generic “new issue detected” message. For example, an analyst can be shown that a host absent from \( A_{t-1} \) is now present in \( A_t \), that it exposes a newly observed service, and that the service fingerprint maps to a specific vulnerability record. The explanatory chain is therefore temporal as well as technical.

For these reasons, drift analysis is not simply an add-on reporting feature in this architecture. It is the mechanism that turns repeated scanning into continuous monitoring.

[Figure 3: Drift Detection Logic Placeholder  
Description: A comparison diagram showing Scan Snapshot at time t-1 and Scan Snapshot at time t, with arrows highlighting newly added assets, removed services, changed ports, and severity-escalated findings. A Diff Engine block in the center outputs prioritized change events.]

Figure 3 should show two structured scan snapshots rather than two raw scan outputs. Assets, services, and findings should be represented as comparable objects on each side. The diff engine in the center should highlight not just additions and removals, but also transformation events such as changed service versions or escalated findings. The output should be labeled as prioritized change events, reinforcing that the purpose of comparison is actionability, not archival display.

### Pseudocode for Drift Comparison

```text
Algorithm: DriftCompare
Input: previous_snapshot, current_snapshot
Output: drift_events

1. index previous assets by asset_key
2. index current assets by asset_key
3. index previous findings by finding_key
4. index current findings by finding_key
5. initialize drift_events as empty list

6. for each asset in current assets:
7.     if asset not in previous assets:
8.         add NEW_ASSET event
9.     else:
10.        compare ports, services, and versions
11.        if differences exist:
12.            add ASSET_CHANGE event(s)

13. for each asset in previous assets:
14.     if asset not in current assets:
15.         add REMOVED_ASSET event

16. for each finding in current findings:
17.     if finding not in previous findings:
18.         add NEW_VULNERABILITY event
19.     else if severity or exploit context increased:
20.         add ESCALATION event

21. for each finding in previous findings:
22.     if finding not in current findings:
23.         add RESOLVED_VULNERABILITY event

24. prioritize drift_events by severity, novelty, and exposure relevance
25. return drift_events
```

# 14. DATA SOURCES AND THREAT INTELLIGENCE INTEGRATION

The system depends on structured public vulnerability intelligence, not as a replacement for scanning, but as the layer that gives scan evidence security meaning. CVE provides standardized identifiers for known vulnerabilities [3]. NVD adds structured descriptions, scoring, references, and related metadata [2]. CPE provides a naming scheme that helps bridge observed service evidence and normalized product identity [4].

In practical terms, the correlation workflow is usually imperfect and inference-based. A scan may observe an HTTP banner, a package version string, or a software family name. That evidence must be interpreted into a product/version candidate, mapped into a CPE-like identifier, and then checked against CVE/NVD records. This process is valuable, but it should be described with care. It is a correlation pipeline, not an oracle.

For a capstone implementation, local storage of vulnerability intelligence is particularly useful. A local lookup database improves repeatability, reduces dependence on live remote calls, and supports faster enrichment during recurring scans. It also allows the engineering team to index or pre-process vulnerability records in a way that simplifies correlation logic. This is a practical design decision, not simply a performance optimization.

Exploit references such as Exploit-DB may be added as supplementary context [13]. When used carefully, they help the reporting layer distinguish between severe findings that are theoretically important and findings that also have a stronger exploitability signal. Even so, such signals should remain advisory. The presence of a public exploit reference does not prove exploitability in the specific observed environment.

This section also has to acknowledge the main source of uncertainty in the system: service identification is rarely perfect. Reverse proxies, customized builds, partial banners, middleware layers, and hidden version information all complicate mapping. That is why evidence-backed reporting matters. A mature system should show not only *what* was matched, but *what was observed* and *how the match was derived*.

[Figure 4: Vulnerability Intelligence Correlation Placeholder  
Description: A diagram showing Service Fingerprint -> CPE Normalization -> CVE Lookup -> Severity/Priority Enrichment -> Evidence-Linked Finding.]

Figure 4 should depict correlation as a pipeline of increasingly structured interpretation. The diagram should show raw service evidence on the left, a normalization step in the middle, and a final evidence-linked finding on the right. The visual message should be that findings emerge from a chain of reasoning rather than a single lookup.

# 15. IMPLEMENTATION DETAILS

## 15.1 Programming Stack

A serious capstone team can implement this system with a compact but capable stack. Python is a sensible primary language because it supports orchestration logic, HTTP services, database integration, scanner control, and rapid prototyping without sacrificing technical clarity. FastAPI suits the backend because it provides lightweight API construction and a clean way to model scan lifecycle operations. Dash and Plotly suit the frontend because they allow a functional analyst dashboard to be built quickly while remaining tied closely to structured backend outputs.

SQLite is a reasonable persistence choice for a prototype or lab deployment. It is simple to distribute, easy to inspect, and sufficient for storing scope records, scan runs, findings, alerts, and historical snapshots. The architecture, however, should remain database-agnostic enough that a later migration to PostgreSQL is straightforward.

## 15.2 API / Backend Implementation

The backend acts as the system’s control plane. It stores monitored scopes, creates scan runs, coordinates background execution, exposes results to the frontend, and maintains the records needed for historical comparison. A RESTful API is appropriate because it separates the dashboard from the underlying monitoring logic and provides a clear boundary between control and processing.

A typical backend for this system includes endpoints for scope creation, scope listing, scan initiation, run status retrieval, log access, asset listing, findings retrieval, alert access, and differential comparison. This API shape is realistic for a capstone project and sufficiently rich to support both demo workflows and future extension.

## 15.3 Scanning Engine Integration

The scanning layer is best implemented through controlled integration with established tooling such as Nmap [1]. The role of the project is not to replace those tools, but to integrate them into a broader monitoring pipeline that preserves structure and history. Scan profiles can be used to expose different levels of depth or aggressiveness, while the orchestration layer ensures that results are parsed into consistent data models.

In a prototype setting, parts of the pipeline may initially be simplified or staged. That is acceptable as long as the system architecture is honest about what is implemented and what remains planned. The important point is that the design admits real scanner integration and treats scanner output as structured evidence.

## 15.4 Scheduler / Continuous Monitoring Logic

Recurring execution is necessary if the system is to support drift detection in a meaningful way. A scheduler therefore creates repeated observations of the same scope under the same or comparable policy. In a practical capstone build, a background scheduler is sufficient to demonstrate recurring execution, scheduled run creation, and historical state accumulation.

However, the implementation should be described carefully. A lightweight scheduler demonstrates the control logic of continuous monitoring, but it is not the same as a fully durable production scheduler. Persisted job definitions, reliable restart behavior, and stronger concurrency management remain natural next steps rather than assumptions of the current prototype.

## 15.5 Database Schema Overview

The database schema is one of the more important implementation elements because the system relies on persisted state to reason about change. At minimum, the schema needs to represent managed scopes, scan runs, logs, assets, findings, and alerts. The model should support both current-state retrieval and historical comparison.

A useful design is to store scan-run metadata separately from asset and finding records, with each observation linked back to the relevant scope and run. This allows the system to reconstruct historical snapshots for the drift engine while also supporting ordinary dashboard views such as “show findings for this run” or “show alert history for this site.”

## 15.6 Dashboard / User Interface

The dashboard is designed as an operational monitoring interface rather than a general administration portal. It should expose the elements analysts care about: current scans, discovered assets, findings by severity, alert status, and differences between recent runs. In a capstone setting, this interface is not incidental. It is the clearest way to demonstrate that the underlying data model and orchestration logic produce useful outputs.

A web-based UI is also a practical delivery choice. It reduces platform overhead and makes iterative testing easier. Although the underlying API can support future clients, the present implementation is most credible when described as a web-first analyst console.

## 15.7 Concurrency, Threading, and Task Handling

Scan execution is naturally asynchronous relative to user interaction. A user should be able to initiate a run, observe progress, and retrieve results without waiting in a blocking request cycle. For that reason, background tasks, worker threads, or comparable execution mechanisms are appropriate.

A capstone implementation does not need a full distributed queue to demonstrate this idea. Thread-based or process-based background execution is sufficient if the system correctly separates request handling from scan processing and ensures that run state is safely persisted during execution.

## 15.8 Persistence Model

Persistence serves three roles in this system. It records execution history, preserves the evidence needed for analyst review, and stores the historical states required for differential analysis. Without that persistence, the proposed drift engine would have nothing meaningful to compare.

This is why the persistence model should be seen as part of the monitoring logic rather than as a back-office detail. The system’s ability to reason across time depends directly on how faithfully it stores scan artifacts and their relationships.

## 15.9 Alert Lifecycle

Alerts are created when the system determines that a change event or finding merits explicit analyst attention. Each alert should retain enough context to be interpretable: the affected scope, the associated run, the type of change, the severity, and a concise explanatory description. Acknowledgement state is also useful, as it distinguishes new operational events from items already reviewed.

This lifecycle can remain simple in a capstone implementation. Even a modest alert model is valuable if it supports clear change communication and fits naturally into the broader drift-aware monitoring approach.

# 16. UML / DESIGN DIAGRAM PLACEHOLDERS

## 16.1 Use Case Diagram

[Figure 5: Use Case Diagram Placeholder  
Description: Security Analyst interacts with Configure Domain, Start Scan, Monitor Scan, View Findings, Compare Drift, Receive Alerts, Generate Reports.]

The use case diagram should show the Security Analyst as the primary actor and the monitoring system as the system boundary. The main use cases should include registering an authorized target, launching a scan, monitoring progress, viewing discovered assets, reviewing findings, comparing scan states, acknowledging alerts, and generating reports. If desired, a Scheduler actor can be shown as a secondary initiator of periodic scans.

## 16.2 Activity Diagram

[Figure 6: Activity Diagram Placeholder  
Description: Start -> Define target -> Discover assets -> Scan services -> Correlate vulnerabilities -> Store snapshot -> Compare drift -> Generate alerts -> Display dashboard -> End.]

The activity diagram should show the monitoring pipeline in execution order, including the important fact that state is stored before comparison occurs. Decision nodes may be added for situations such as “no assets discovered,” “no new drift detected,” or “findings generated.”

## 16.3 Sequence Diagram

[Figure 7: Sequence Diagram Placeholder  
Description: User -> UI -> Backend -> Recon Agent -> Scan Agent -> Vulnerability Agent -> Drift Engine -> Alert Engine -> Database -> UI response.]

The sequence diagram should show the request lifecycle and the movement of control across components. It should begin with user or scheduler initiation, continue through backend orchestration and agent invocation, and end with results being stored and made visible to the UI.

## 16.4 Class Diagram

[Figure 8: Class Diagram Placeholder  
Description: Classes such as Site, Asset, ScanRun, ScanResult, VulnerabilityRecord, DriftEvent, Alert, User, and SchedulerJob with key relationships.]

The class diagram should focus on domain objects and their relationships rather than low-level implementation details. A `Site` should own multiple `ScanRun` objects. Each `ScanRun` should relate to asset and finding records. Alerts should be linked to the affected scope or run. A `DriftEvent` abstraction may be shown explicitly even if it is generated dynamically in the initial implementation.

# 17. ALGORITHMS

## 17.1 Algorithm 1: Asset Discovery Workflow

```text
Input: authorized_scope, discovery_policy
Output: discovered_assets

1. validate that the scope is authorized and well formed
2. initialize discovered_assets as empty set
3. derive candidate hosts from scope
4. for each candidate host:
5.     perform bounded reachability or discovery check
6.     if host is responsive or discoverable:
7.         normalize host identifier
8.         record IP, hostname, and discovery timestamp
9.         add host to discovered_assets
10. return discovered_assets
```

## 17.2 Algorithm 2: Vulnerability Correlation Workflow

```text
Input: service_fingerprints, vulnerability_database
Output: vulnerability_findings

1. initialize vulnerability_findings as empty list
2. for each fingerprint in service_fingerprints:
3.     normalize service name and version
4.     infer candidate product identifiers
5.     map candidate products to CPE-like identifiers
6.     query vulnerability_database for matching CVEs
7.     for each matched CVE:
8.         build evidence string from observed fingerprint
9.         attach severity and reference metadata
10.        append structured finding to vulnerability_findings
11. return vulnerability_findings
```

## 17.3 Algorithm 3: Drift Comparison Workflow

```text
Input: previous_snapshot, current_snapshot
Output: drift_events

1. index previous assets and findings
2. index current assets and findings
3. initialize drift_events as empty list
4. compare asset membership between snapshots
5. compare service and port attributes for shared assets
6. compare finding membership between snapshots
7. compare severity or exploit context for shared findings
8. create structured events for meaningful changes
9. rank drift_events by severity and novelty
10. return drift_events
```

## 17.4 Algorithm 4: Alert Prioritization Workflow

```text
Input: current_findings, drift_events
Output: prioritized_alerts

1. initialize prioritized_alerts as empty list
2. for each drift_event:
3.     assign base priority from event type
4.     increase priority if associated finding is critical
5.     increase priority if exploit context exists
6.     increase priority if the event introduces new exposure
7.     build explainable alert record
8. sort alerts by descending priority
9. return prioritized_alerts
```

# 18. EVALUATION STRATEGY

## 18.1 Evaluation Goals

A credible evaluation of this system should answer several distinct questions. First, does the system function correctly as an end-to-end monitoring pipeline? Second, are scan states stored in a form that actually supports later comparison? Third, does the drift engine identify known changes reliably? Fourth, is the resulting output useful to an analyst? Fifth, how does the architecture behave as monitored data volume grows?

These questions matter because the project’s contribution is architectural. The evaluation therefore has to test not only whether a scan runs, but whether the system behaves as a monitoring platform.

## 18.2 Completed Evaluation

At the current capstone stage, the most defensible evaluation is **functional validation**. This includes verifying that the system can represent monitored scopes, execute scans, persist artifacts, retrieve assets and findings, and perform differential comparison across controlled scan states. It is also reasonable to validate the internal coherence of the data model and the plausibility of the reporting outputs.

The completed evaluation can therefore include:

- end-to-end workflow verification from scope definition to result presentation,
- validation that assets and findings are persisted as structured records,
- scenario-based verification of drift detection under known controlled differences,
- inspection of alert and reporting outputs for evidentiary completeness.

## 18.3 Core Evaluation Metrics

The evaluation of the current prototype is centered on eight metrics that map directly to the system's main claims. These metrics are intentionally aligned with the implemented pipeline rather than with abstract model-benchmark conventions. The system is not a classifier in the narrow sense; it is a monitoring framework. It should therefore be judged by whether it executes reliably, correlates vulnerabilities credibly, compares consecutive scans correctly, suppresses unnecessary alert noise, and communicates risk clearly to both technical and non-technical audiences.

The first metric is **Scan Success Rate (SSR)**, defined as the proportion of initiated scan runs that reach a valid terminal `done` state without pipeline failure. This measures end-to-end execution reliability.

The second metric is **Vulnerability Correlation Precision (VCP)**, defined as the fraction of reported vulnerability matches that are judged correct when compared against known service banners or controlled seeded scenarios. This measures whether the correlation stage is generating defensible findings rather than noisy overmatching.

The third, fourth, and fifth metrics are the core drift-analysis metrics: **Drift Detection Precision (DDP)**, **Drift Detection Recall (DDR)**, and **Drift Detection F1 (DDF1)**. These are computed over controlled inter-scan changes such as newly introduced findings, resolved findings, newly opened ports, or newly discovered assets. Drift Detection F1 is especially important because it gives one compact measure of how well the system balances missed changes against spurious ones.

The sixth metric is **Alert Deduplication Rate (ADR)**, defined as the proportion of repeated unresolved alerts that are successfully suppressed rather than reissued on every run. This is important because the project argues that change-aware monitoring should reduce operational noise, not simply restate the same issues every time.

The seventh metric is **Prioritization Quality (PQ)**, defined as how consistently the ranking logic elevates operationally important findings such as KEV-flagged or high-EPSS vulnerabilities above lower-signal issues. In the current implementation, this metric reflects the effect of combined CVSS, KEV, EPSS, and exploit-presence scoring.

The eighth metric is **Explainability Score (ES)**, defined as a stakeholder-facing clarity measure for the plain-language explanation layer. A practical way to compute it is as the average rating from a small reviewer group on a 1-5 scale, later normalized to 100 if needed. This metric matters because the current system explicitly includes a non-LLM explainability layer intended for reviewers who are not cybersecurity specialists.

A fuller future evaluation should also examine timing and scaling behavior. Suitable secondary performance metrics include overall scan completion time, vulnerability lookup latency, drift comparison time, alert generation latency, and dashboard response time under increasing historical load. The drift comparison logic is expected to scale approximately linearly with snapshot size when implemented with keyed dictionaries or indexed relations, but that should be verified empirically rather than assumed.

## 18.4 Drift Engine Correctness

Because drift analysis is the strongest technical contribution of the work, correctness evaluation is especially important. A straightforward strategy is to construct successive scan states with controlled differences: for example, one new host, one removed host, one new service, or one newly correlated vulnerability. The engine can then be checked for whether it emits the expected drift events and suppresses nonexistent ones.

This kind of scenario-driven validation is appropriate for a capstone. It does not require inflated benchmark claims, but it still tests the system where it matters most.

## 18.5 Performance and Scalability Considerations

Scalability should be evaluated at both the processing and persistence layers. As the number of monitored scopes and historical runs increases, the backend must retrieve and compare more data, and the dashboard must avoid turning every refresh into an expensive full-history query. These concerns are especially relevant if the system retains many snapshots over time.

For the present prototype, the goal is not to claim enterprise-scale throughput, but to identify where scaling pressure will appear and how the architecture can accommodate later improvements.

## 18.6 Explainability and Analyst Value

Usability in this context means more than interface polish. The more important question is whether the system makes the analyst’s job clearer. Does highlighting change reduce noise? Do evidence-backed alerts make results easier to trust? Does the dashboard provide a better understanding of posture evolution than a repeated list of scanner findings?

In the current implementation, analyst value is reinforced by a rule-based explainability layer that translates technical findings into plain-language summaries, business-impact labels, priority explanations, and recommended next steps. Because this layer is deterministic and grounded in stored evidence fields, it can be evaluated directly rather than described only as a design aspiration. A suitable explainability assessment can ask reviewers whether they can understand what the issue is, why it matters, and what action should be taken without reading raw CVE text.

Formal user studies may be outside the immediate scope of the capstone, but structured walkthroughs, scenario-based demonstrations, and small reviewer-based clarity scoring can still provide useful evidence of analyst value.

**[Table Placeholder: Core Evaluation Metrics for VulnPilot]**

**Table 2: Core Evaluation Metrics and How They Should Be Measured**

| Metric | Definition | Why It Matters | Current Use |
|---|---|---|---|
| Scan Success Rate (SSR) | Completed runs / total initiated runs | Measures end-to-end reliability of the monitoring pipeline | Suitable for current prototype validation |
| Vulnerability Correlation Precision (VCP) | Correct vulnerability matches / total reported matches | Measures whether service-to-CVE correlation is defensible | Suitable for controlled service-banner validation |
| Drift Detection Precision (DDP) | Correctly reported changes / total reported changes | Measures false-positive drift noise | Suitable for controlled consecutive-scan tests |
| Drift Detection Recall (DDR) | Correctly reported changes / total actual seeded changes | Measures missed drift events | Suitable for controlled consecutive-scan tests |
| Drift Detection F1 (DDF1) | Harmonic mean of drift precision and recall | Provides one compact score for change-detection quality | Primary effectiveness metric for this project |
| Alert Deduplication Rate (ADR) | 1 - (duplicate unresolved alerts / total alerts) | Measures whether the platform reduces repeated operational noise | Suitable for repeated-run alert analysis |
| Prioritization Quality (PQ) | Proportion of KEV/high-EPSS findings ranked near the top | Measures usefulness of combined CVSS + KEV + EPSS + exploit scoring | Suitable for current prioritization validation |
| Explainability Score (ES) | Average reviewer clarity rating for plain-language explanations | Measures value to non-technical or mixed stakeholders | Suitable for small-scale reviewer assessment |

The evaluation results should be interpreted in two layers. The first layer consists of the controlled validation metrics described above. These are intended to verify correctness under known conditions and should be presented as seeded validation results rather than as universal benchmark figures. The second layer consists of live operational metrics derived from accumulated prototype runs. These reflect ongoing system behavior in the current deployment state and are useful for demonstrating runtime reliability, alert noise characteristics, prioritization behavior, and explanation coverage over time.

Accordingly, the paper should state that the controlled metrics demonstrate that the system behaves correctly in a reproducible scenario with known ground truth, while the live operational metrics illustrate how the prototype behaves during normal use. The paper should not claim that the controlled validation scores represent universal real-world precision or recall across arbitrary environments, nor should they be framed as internet-scale or production-scale benchmark results. They are best understood as correctness-oriented prototype validation combined with live operational telemetry.

# 19. RESULTS AND DISCUSSION

The most defensible result of the present work is that it demonstrates a coherent way to build continuous vulnerability monitoring as a stateful system rather than as a repeated scan launcher. Even at prototype level, that is not trivial. The system links scope management, recurring execution, service enumeration, vulnerability correlation, historical persistence, drift analysis, and reporting into a single pipeline with clear internal boundaries.

The practical strength of the design lies in the way those boundaries reinforce one another. Discovery output feeds scanning. Scanning produces structured evidence for intelligence correlation. Correlated findings are stored as part of a persistent snapshot. Persisted snapshots enable drift reasoning. Drift reasoning enables more meaningful alerting. That chain gives the multi-agent architecture practical substance. The system does not become multi-agent because it is described that way; it becomes multi-agent because each stage owns a distinct transformation in the monitoring workflow.

The drift-aware component is the clearest value-add. In operational terms, a repeated finding is often less urgent than a new exposure event. A newly observed host, an opened port, or a newly matched critical vulnerability is easier to act on than a full findings list that largely duplicates earlier output. The current system design demonstrates how that distinction can be encoded directly in the platform.

Another useful outcome is the emphasis on evidence. By linking findings and alerts to service observations and historical comparison, the system moves toward outputs that analysts can inspect rather than merely receive. This matters because trust in automated security tooling depends heavily on whether results can be understood and verified.

At the same time, the project should be discussed with appropriate restraint. The prototype does not claim production-scale robustness, perfect fingerprinting, or complete vulnerability certainty. Its contribution is architectural and methodological. It shows that a capstone team can build a serious monitoring-oriented system that treats change over time as the central analytical object. That is a meaningful result, even without exaggerated performance claims.

# 20. LIMITATIONS

Several limitations shape both the current implementation and the interpretation of its outputs.

First, the system depends on what the scan can actually observe. Network restrictions, incomplete reachability, hidden services, proxy layers, and authorization boundaries all constrain visibility. If an asset cannot be observed, it cannot be represented in the resulting posture model.

Second, service identification is inherently uncertain. Banner strings may be incomplete or misleading, and product normalization can introduce ambiguity. The vulnerability correlation stage therefore risks both false positives and false negatives. This is not unique to the present system, but it remains a central limitation.

Third, the persistence approach suitable for a capstone prototype is not automatically suitable for large operational deployments. A lightweight relational backend simplifies development, but high concurrency, large historical datasets, and multi-user access would require stronger storage and query design.

Fourth, continuous scheduling in a prototype environment remains lighter than a true production scheduler. Durable job persistence, restart-safe behavior, queue semantics, and distributed execution control are natural areas for improvement.

Fifth, exploitability context is limited. Public exploit references or prioritization signals are helpful, but they do not provide environment-specific proof of exploitability. The system therefore supports prioritization, not exploit verification.

Sixth, the agent-based design introduces coordination overhead. Modular systems are easier to reason about, but only if the contracts between stages are well maintained. Poorly aligned data contracts can create brittle behavior across the pipeline.

Seventh, the current implementation emphasis is on a web-based prototype. The service layer is extensible, but native mobile deployment is not yet part of the validated contribution.

Finally, legal and ethical constraints remain central. Any system that automates scanning must remain tightly bounded by authorized scope and clear operational policy. This limitation is not incidental to the work; it is part of responsible system design.

# 21. FUTURE WORK

Several extensions would make the system significantly stronger.

One important direction is richer exploitability-aware prioritization, including more complete use of KEV-style signals, exploit maturity data, and contextual ranking beyond severity alone. Another is adaptive scheduling, where the monitoring cadence is adjusted according to prior drift frequency, asset criticality, or recent operational changes rather than using a single fixed interval.

A third direction is improved fingerprinting and normalization. Better service parsing, protocol-aware enrichment, and cross-source product resolution would strengthen the correlation stage directly. A fourth is graph-based attack surface reasoning, where assets and services are represented not only as isolated records but as related nodes in a broader exposure graph.

From an engineering perspective, future work should also include stronger persistence and scheduling infrastructure, multi-tenant deployment support, better asynchronous execution, and a more scalable database backend. Analyst feedback loops are another promising area: if users can mark findings as useful, noisy, or already understood, the platform could gradually improve its prioritization strategy.

Finally, a carefully constrained language-model-based explanation layer could be explored. Such a layer should never invent findings or replace structured evidence, but it could help summarize technically grounded outputs into clearer analyst-facing prose when tightly bounded by the data model.

# 22. CONCLUSION

This paper examined the design of **An Autonomous Multi-Agent System for Automated Cybersecurity Reconnaissance and Vulnerability Scanning** as a practical, research-oriented capstone project. The central problem is straightforward: one-time or infrequent scans are no longer sufficient in environments where exposed assets and services change continuously. What matters operationally is not only what exists, but what changed.

The proposed system addresses that problem through a modular monitoring pipeline composed of agents for discovery, service enumeration, vulnerability intelligence correlation, drift analysis, and reporting. Its most important contribution is the treatment of historical comparison as a core monitoring function rather than a peripheral feature. By preserving scan state and comparing it over time, the system can highlight newly introduced exposure and provide a more useful view of security posture than static scan output alone.

The work is intentionally grounded. It does not claim to replace mature scanners or to solve vulnerability assessment in a general sense. Its value lies in showing how continuous monitoring, bounded autonomy, structured persistence, and evidence-backed reporting can be assembled into a coherent system that is both technically credible and achievable within a serious capstone project. That makes it a useful foundation for further work on practical autonomous security monitoring.

# 23. ACKNOWLEDGMENT

The authors would like to express sincere gratitude to **[Institution Name]**, **[Department Name]**, and **[Supervisor/Guide Name]** for their academic guidance, technical feedback, and sustained support throughout the development of this capstone project. The authors also acknowledge the contribution of **[Team Member Names]** for their collaboration in system design, implementation discussions, testing support, and documentation efforts.

# 24. REFERENCES

[1] G. F. Lyon, *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning*. Sunnyvale, CA, USA: Insecure, 2009.

[2] National Institute of Standards and Technology, “National Vulnerability Database (NVD),” Gaithersburg, MD, USA. [Online]. Available: https://nvd.nist.gov/

[3] The MITRE Corporation, “Common Vulnerabilities and Exposures (CVE),” McLean, VA, USA. [Online]. Available: https://www.cve.org/

[4] D. Waltermire, S. Quinn, K. Scarfone, and A. Halbardier, “The Common Platform Enumeration Naming Specification Version 2.3,” NIST Interagency Report 7695, 2011.

[5] K. Scarfone, M. Souppaya, A. Cody, and A. Orebaugh, “Technical Guide to Information Security Testing and Assessment,” NIST Special Publication 800-115, 2008.

[6] R. Johnson, M. Badger, D. Waltermire, J. Snyder, and C. Skorupka, “Guide for Applying the Risk Management Framework to Federal Information Systems: A Security Life Cycle Approach,” NIST Special Publication 800-37, and related continuous monitoring guidance in NIST SP 800-137, reference candidate for continuous monitoring context.

[7] Forum of Incident Response and Security Teams (FIRST), “Common Vulnerability Scoring System v3.1: Specification Document,” 2019.

[8] A. Kott, C. Arnold, and T. Abdelzaher, “Autonomous Intelligent Cyber-Defense Agent (AICA) Reference Architecture,” reference candidate, in research on autonomous cyber defense systems.

[9] M. Wooldridge, *An Introduction to MultiAgent Systems*, 2nd ed. Hoboken, NJ, USA: Wiley, 2009.

[10] P. K. Manadhata and J. M. Wing, “An Attack Surface Metric,” *IEEE Transactions on Software Engineering*, vol. 37, no. 3, pp. 371-386, 2011.

[11] M. Howard, J. Pincus, and J. M. Wing, “Measuring Relative Attack Surfaces,” in *Computer Security in the 21st Century*, New York, NY, USA: Springer, 2005, pp. 109-137.

[12] J. Spring, A. O’Donnell, T. Manion, and D. Householder, “The Exploit Prediction Scoring System (EPSS),” reference candidate for exploitability prioritization and vulnerability triage research.

[13] Offensive Security, “Exploit Database (Exploit-DB),” [Online]. Available: https://www.exploit-db.com/

[14] T. Miller, “Explanation in Artificial Intelligence: Insights from the Social Sciences,” *Artificial Intelligence*, vol. 267, pp. 1-38, 2019.

[15] A. B. Arrieta et al., “Explainable Artificial Intelligence (XAI): Concepts, Taxonomies, Opportunities and Challenges toward Responsible AI,” *Information Fusion*, vol. 58, pp. 82-115, 2020.

[16] Reference candidate: survey literature on explainable AI in cybersecurity, such as an IEEE Access or ACM Computing Surveys article focused on interpretable cyber defense and security analytics.

[17] National Institute of Standards and Technology, “Guide to Enterprise Patch Management Planning: Preventive Maintenance for Technology,” NIST Special Publication 800-40, reference candidate for vulnerability management practice.

[18] MITRE, “Common Weakness Enumeration (CWE),” [Online]. Available: https://cwe.mitre.org/ — reference candidate for broader weakness classification context.

[19] S. Noel and S. Jajodia, “Managing Attack Graph Complexity through Visual Hierarchical Aggregation,” reference candidate relevant to attack surface reasoning and future graph-based expansion.

[20] Reference candidate: recent work on external attack surface management and continuous exposure monitoring in academic or industrial security literature, to be finalized according to the institution’s reference style requirements.

# 25. APPENDICES

## Appendix A: Proposed Technology Stack

| Layer | Prototype Choice | Rationale | Scale-Up Option |
|---|---|---|---|
| Backend service | FastAPI | Lightweight REST API development, clear endpoint structure | FastAPI with worker queue and service decomposition |
| Agent orchestration | Python modules / structured pipeline stages | Transparent, auditable, feasible for capstone scope | Message queue or workflow engine |
| Discovery and scanning | Nmap and bounded discovery logic | Mature scanning primitives and service detection | Distributed scanning workers |
| Threat intelligence | Local CVE/NVD/CPE index | Faster repeated lookups and reproducible testing | PostgreSQL or search-backed enrichment service |
| Operational database | SQLite | Easy local deployment and historical state storage | PostgreSQL |
| Frontend | Dash / Plotly | Rapid analyst dashboard construction | React or multi-client frontends |
| Scheduling | Background scheduler | Supports recurring monitoring in prototype | Persistent DB-backed scheduler |
| Reporting | Structured dashboard + generated summary output | Explainable and demo-friendly | PDF/report pipeline and workflow integration |

## Appendix B: Example API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/sites` | Register an authorized monitored scope |
| `GET` | `/sites` | List configured monitored scopes |
| `POST` | `/sites/{site_id}/scan` | Trigger a scan for a managed site |
| `GET` | `/sites/{site_id}/diff` | Retrieve differential results between recent snapshots |
| `POST` | `/scan` | Start a scan run from supplied scope data |
| `GET` | `/scan/{run_id}/status` | Retrieve run status and progress |
| `GET` | `/scan/{run_id}/logs` | Retrieve run log stream |
| `GET` | `/assets` | Retrieve asset records by run or scope |
| `GET` | `/findings` | Retrieve vulnerability findings by run or scope |
| `PATCH` | `/findings/{finding_id}/workflow` | Update finding workflow state |
| `GET` | `/alerts` | Retrieve alert records |
| `POST` | `/alerts/{alert_id}/acknowledge` | Acknowledge an alert |

## Appendix C: Suggested Database Schema

| Table | Key Fields | Purpose |
|---|---|---|
| `sites` | `site_id`, `name`, `primary_domain`, `allowed_scopes`, `policy`, `schedule`, `auth_confirmed` | Stores authorized monitoring targets |
| `scan_runs` | `run_id`, `site_id`, `status`, `profile`, `created_at` | Stores scan execution lifecycle |
| `scan_logs` | `id`, `run_id`, `timestamp`, `level`, `message` | Stores progress and diagnostic logs |
| `assets` | `asset_id`, `run_id`, `site_id`, `host`, `ip`, `open_ports`, `risk_score` | Stores discovered asset state per run |
| `findings` | `finding_id`, `run_id`, `site_id`, `cve_id`, `severity`, `evidence`, `remediation` | Stores correlated vulnerability records |
| `alerts` | `alert_id`, `site_id`, `run_id`, `trigger_type`, `severity`, `detail`, `acknowledged` | Stores prioritized change-driven alerts |
| `scheduler_jobs` | `job_id`, `site_id`, `cadence`, `next_run_at`, `last_run_at`, `status` | Suggested future persistent scheduler table |
| `vuln_lookup` | `cve_id`, `description`, `cvss`, `references`, `cpe_links` | Stores locally indexed vulnerability intelligence |

## Appendix D: Figure Creation Checklist

| Figure | Title | What It Should Show |
|---|---|---|
| Figure 1 | High-Level System Architecture | User/Analyst, Dashboard/UI, Backend Orchestrator, five agents, application DB, threat intelligence DB, control-flow and data-flow arrows |
| Figure 2 | End-to-End Processing Pipeline | Target input, discovery, host validation, scan, service detection, vulnerability correlation, snapshot storage, drift comparison, alert generation, dashboard output |
| Figure 3 | Drift Detection Logic | Snapshot at time \( t-1 \), snapshot at time \( t \), diff engine in between, annotations for new assets, removed assets, changed services, new vulnerabilities |
| Figure 4 | Vulnerability Intelligence Correlation | Service fingerprint, product normalization, CPE mapping, CVE lookup, severity enrichment, evidence-linked finding |
| Figure 5 | Use Case Diagram | Security Analyst actor and use cases such as configure scope, start scan, monitor run, view findings, compare drift, acknowledge alerts, generate report |
| Figure 6 | Activity Diagram | Start-to-end workflow from scope definition through report generation with decision points |
| Figure 7 | Sequence Diagram | Interaction sequence among User, UI, Backend, agents, database, and alert/report return path |
| Figure 8 | Class Diagram | Domain entities such as Site, ScanRun, Asset, VulnerabilityRecord, DriftEvent, Alert, SchedulerJob, and their relationships |
