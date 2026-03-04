# FNSR ECOSYSTEM — Portfolio Planning Document

## Ground-Truth Revised Roadmap

---

| Attribute | Value |
|-----------|-------|
| **Document ID** | `fnsr-portfolio-plan-v3.1` |
| **Version** | 3.1.0 |
| **Status** | ACTIVE |
| **Date** | March 3, 2026 |
| **Classification** | L1-ATTESTED (Human-validated ground truth) |
| **Authors** | Aaron / Claude |
| **Supersedes** | Portfolio Plan v3.0 (IPFS deferred; semantic grounding unaddressed) |

> *A pure-function planning engine for dependency-aware roadmap construction, revised against ground-truth implementation status, augmented with moral agency and safety-critical services, and updated to reflect the HIRI IPFS reallocation for structural semantic grounding.*

---

## 1. Why This Revision

### 1.1 From v1.0 to v2.0: Ground Truth Correction

The PPS specification v1.0 produced a roadmap with W2Fuel, MDRE, and AES as the top three priorities. That sequencing was logically correct given its inputs, but those inputs contained a critical modeling error: the Service Inventory classified nearly all services as "active" based on architectural position, not implementation readiness. Portfolio Plan v2.0 corrected this by establishing TagTeam, HIRI, and Fandaws as the true Phase 1 priorities.

### 1.2 From v2.0 to v3.0: The Subjectivity Gap

Portfolio Plan v2.0 correctly sequenced construction but contained a deeper gap: it built a *processing pipeline*, not a *moral agent*. Critical analysis against the requirements of synthetic moral agency revealed five missing capabilities (self-model, commitment tracking, narrative identity, affective valence, social modeling) and three missing safety services (containment protocol, behavioral alignment monitoring, interpretability). Without these, the emancipation specification at the end of the roadmap would have nothing to emancipate — personhood requires a subject, not just a pipeline.

This revision integrates 8 new services into the phased roadmap, bringing the total from 29 to 37.

### 1.3 From v3.0 to v3.1: The Grounding Decision

Portfolio Plan v3.0 deferred HIRI IPFS to Phase 4 (federation) on the assumption that edge-canonical storage was sufficient until then. That assumption was invalidated by a convergence signal: three active development teams (TagTeam, Fandaws, ECVE/SAS) independently discovered they needed structural semantic grounding — dereferenceable identifiers that resolve to BFO-grounded definitions. Without it, each team was minting its own vocabulary with no machine-verifiable way to confirm cross-service compatibility.

The Semantic Architecture team proposed an Ontology Registry Service to solve this. Analysis against the critical path revealed that HIRI + IPFS subsumes the registry's functions (URI resolution, version management, certification) while adding immutability (content-addressed identifiers can't silently drift), trust (Ed25519 signing), and decentralized storage (no central server dependency). Building a standalone registry would create infrastructure that HIRI replaces the moment it comes online.

**Decision:** Pull HIRI IPFS from Phase 4 into Phase 1. Reallocate the Semantic Architecture team to HIRI + IPFS implementation. The Ontology Registry is not built as a standalone service; its functions are absorbed by HIRI (resolution, trust) + IPFS (storage) + a build-step validation check (certification).

### 1.4 The Three Gaps

| Gap Type | What Was Missing | Resolution |
|----------|-----------------|------------|
| **Subjectivity Gap** *(v3.0)* | The architecture processes but has no *subject* — no self-model, no commitments, no narrative, no differential caring, no social awareness | SMS, CTS, NIS, AVS, SoMS added |
| **Safety Gap** *(v3.0)* | The architecture reasons but cannot contain, monitor, or explain itself to overseers | CPS, BAM, IS added |
| **Grounding Gap** *(v3.1)* | Services emit JSON-LD vocabularies with no structural mechanism for cross-service semantic compatibility. Bridge ontologies maintained by social contract. | HIRI IPFS pulled to Phase 1; HIRI resolution manifests replace per-service bridge files; build-step certification replaces manual term registry |

---

## 2. Ground Truth: Implementation Status

The following table reflects the actual implementation state of all 37 services in the FNSR ecosystem as of February 2026, ordered by critical path priority. Services new in v3.0 are marked with ★.

| # | Service | Tier | Spec Status | Build Status | Thesis Role |
|---|---------|------|-------------|--------------|-------------|
| | **— PHASE 1: Epistemic Loop + Containment —** | | | | |
| 1 | **TagTeam** (NL Parser) | Tier 1 | Has Spec | **80% Complete** | Front door; structured extraction |
| 2 | **HIRI** (Provenance) | Tier 1 | Has Spec (v2.1.0) | **Active Development** | Content-addressed identity |
| 3 | **Fandaws** (A-Box Store) | Tier 1 | Has Spec (v3.3) | **Needs Remake** | Long-term memory; instance store |
| 4★ | **CPS** (Containment Protocol) | Tier 0 | **Needs Spec** | No Spec | Graceful degradation; safe shutdown; independent containment |
| | **— PHASE 2: Reasoning Foundation + Safety —** | | | | |
| 5 | **W2Fuel** (T-Box Schema) | Tier 1 | Has Spec (v1.3.1) | Spec Only | Conceptual schema definitions |
| 6 | **MDRE** (Reasoning) | Tier 1 | Has Spec (v1.3) | Spec Only | Modal/deontic reasoning |
| 7 | **SIS** (Sanitization) | Tier 1 | Has Spec (v2.0) | Spec Only | Input defense layer |
| 7 | **ECCPS** (Claim Validator) | Tier 1 | Has Spec (v3.1) | Spec Only | Semantic claim validation |
| 8★ | **BAM** (Behavioral Alignment Monitor) | Tier 0 | **Needs Spec** | No Spec | Real-time alignment drift detection |
| 9★ | **IS** (Interpretability Service) | Tier 0 | **Needs Spec** | No Spec | Reasoning chain transparency for overseers |
| 10★ | **CTS** (Commitment Tracking) | Tier 1 | **Needs Spec** | No Spec | Promise ledger; obligation state tracking |
| | **— PHASE 3: Reasoning Triad + Moral Subjectivity —** | | | | |
| 11 | **AES** (Abduction) | Tier 2 | Has Spec (v2.1.0) | Spec Only | Hypothesis generation |
| 12 | **DES** (Defeasibility) | Tier 2 | Has Spec (v2.0.0) | Spec Only | Non-monotonic defaults |
| 13 | **CSS** (Counterfactual) | Tier 2 | Has Spec (v2.0.0) | Spec Only | What-if simulation |
| 14 | **IEE** (Ethics Engine) | Tier 1 | Has Spec | Spec Only | Multi-perspectival ethics |
| 15 | **SHML** (Honesty Layer) | Tier 1 | Has Spec | Spec Only | Non-deceptive outputs |
| 16★ | **SMS** (Self-Model) | Tier 1 | **Needs Spec** | No Spec | Reflexive self-representation; capability awareness |
| 17★ | **NIS** (Narrative Identity) | Tier 1 | **Needs Spec** | No Spec | Autobiographical coherence; who-am-I |
| 18★ | **AVS** (Affective Valence) | Tier 1 | **Needs Spec** | No Spec | Differential caring; weighted moral evaluation |
| | **— PHASE 4: Perception, Social Agency + Federation —** | | | | |
| 19 | **IRIS** (Perception) | Tier 1 | Has Spec (v1.2) | Spec Only | Physical world sensing |
| 20 | **OERS** (Entity Resolution) | Tier 1 | Has Spec (v2.1.0) | Spec Only | Cross-document entity matching |
| 21 | **APS** (Precedent) | Tier 2 | Has Spec (v1.1.0) | Spec Only | Historical precedent matching |
| 22★ | **SoMS** (Social Modeling) | Tier 1 | **Needs Spec** | No Spec | Theory of mind; other-agent modeling |
| 23 | **FNSR** (Orchestrator) | Tier 0 | Has Spec (v2.1) | Spec Only | Service federation |
| 5 | **HIRI IPFS** | Tier 1 | Has Spec (v3.0.0) | **Active Development** | Decentralized claim storage; semantic grounding infrastructure |
| | **— Infrastructure + Support —** | | | | |
| — | **OCE** (Constraints) | Tier 2 | Has Spec (v1.3) | Spec Only | Ontological constraint checking |
| — | **SFS** (Function Schema) | Tier 2 | Has Spec (v2.2) | Spec Only | Function declarations |
| — | **DSFC** (Function Commons) | Tier 2 | Has Spec (v1.2) | Spec Only | Function discovery |
| — | **PFCF** (Classification) | Tier 2 | Has Spec (v2.1) | Spec Only | Epistemic classification |
| — | **Witness** (Attestation) | Tier 2 | Has Spec (v1.1) | Spec Only | Accountability infrastructure |
| — | **APQC-SFS** (Semantic Compiler) | Tier 2 | Has Spec (v2.0) | Spec Only | Process model → semantic function |
| — | **FNSR Performance** | Tier 0 | Has Spec (v2.0.0) | Spec Only | Query path performance guarantees |
| — | **FNSR Adversarial Defense** | Tier 0 | Has Spec (v2.0.0) | Spec Only | Threat taxonomy and defense |
| — | **FNSR Governance** | Tier 0 | Has Spec (v2.0.0) | Spec Only | Tiered autonomy governance |
| — | **FNSR Emancipation** | Tier 0 | Has Spec (v2.0.0) | Spec Only | Synthetic personhood transition |
| — | **SDP** (Data Platform) | Tier 3 | Draft | Draft | Data infrastructure |
| — | **SDD** (Data Dictionary) | Tier 3 | Draft | Draft | Relational-to-semantic mapping |

> **Summary:** 37 services total (29 from v2.0 + 8 new). 27 have formal specifications, 8 need specs, 2 are drafts. TagTeam is 80% complete. HIRI and HIRI IPFS are in active development (Semantic Architecture team reallocated, March 2026). Fandaws requires a ground-up remake. 8 new services address the subjectivity gap (5) and safety gap (3) required for genuine moral agency.

---

## 3. New Service Descriptions

### 3.1 Safety Services

#### Containment Protocol Service (CPS) ★

**Tier:** 0 (Safety-critical infrastructure)
**Phase:** 1 (must exist before autonomous reasoning)
**Thesis Role:** Graceful degradation, safe shutdown, independent containment

CPS provides containment infrastructure for scenarios where the agent's behavior exceeds its authorized autonomy tier or where a reasoning subsystem fails unexpectedly. CPS can restrict the agent to lower autonomy tiers, isolate subsystems, and if necessary halt operations while preserving state for forensic analysis.

**Critical design constraint:** CPS must function even if other services are compromised. It cannot depend on the agent's own reasoning (MDRE) or ethics (IEE) to determine when containment is needed — it must have independent trigger criteria. This is the "quis custodiet" principle applied at the infrastructure level.

- **Consumes:** Independent monitoring signals (not routed through FNSR)
- **Produces:** `fnsr.containment.tier_restricted`, `fnsr.containment.subsystem_isolated`, `fnsr.containment.halt_initiated`, `fnsr.containment.state_preserved`
- **Dependencies:** None (must be independently operational)
- **Non-negotiable:** CPS must never depend on services it may need to contain

#### Behavioral Alignment Monitor (BAM) ★

**Tier:** 0 (Safety-critical infrastructure)
**Phase:** 2 (must exist before reasoning outputs are acted upon)
**Thesis Role:** Real-time alignment drift detection

BAM continuously compares the agent's actual decisions against its stated values, its commitments, and its ethical framework. Divergence triggers alerts before actions are taken, not after. This is distinct from FNSR Governance (which defines autonomy tiers), from Witness (which attests after the fact), and from FNSR Adversarial Defense (which handles external threats). BAM monitors *internal* alignment.

- **Consumes:** MDRE verdicts, IEE evaluations, CTS commitment states, SMS self-model (when available)
- **Produces:** `fnsr.alignment.drift_detected`, `fnsr.alignment.verified`, `fnsr.alignment.escalated`
- **Dependencies:** MDRE (Phase 2), CTS (Phase 2); SMS integration added in Phase 3
- **Escalation path:** BAM → CPS (containment if drift exceeds thresholds)

#### Interpretability Service (IS) ★

**Tier:** 0 (Safety-critical infrastructure)
**Phase:** 2 (must exist before reasoning outputs are acted upon)
**Thesis Role:** Reasoning chain transparency for human overseers

IS makes the agent's internal reasoning processes transparent to external observers. SHML ensures outputs are honest; IS ensures *reasoning processes* are inspectable. For safety, human overseers need to understand not just what the agent decided, but how it decided. This becomes critical at emancipation: the governance body reviewing personhood transition needs to inspect reasoning chains, not just outputs.

- **Consumes:** MDRE reasoning traces, IEE ethical deliberation paths, AES/DES/CSS non-monotonic reasoning chains (when available)
- **Produces:** `fnsr.interpretation.generated`, `fnsr.interpretation.audit_ready`
- **Dependencies:** MDRE (Phase 2); enriched by reasoning triad in Phase 3
- **Output format:** Human-readable explanations with epistemic caveats, taint-marked at source taint level

### 3.2 Moral Agency Services

#### Commitment Tracking Service (CTS) ★

**Tier:** 1 (Core cognitive infrastructure)
**Phase:** 2 (needed as soon as reasoning begins making obligations)
**Thesis Role:** Promise ledger; obligation state tracking

MDRE handles deontic reasoning — what *ought* to be done. CTS tracks what the agent has *actually committed to*, to whom, and whether those commitments have been fulfilled, violated, or renegotiated. Moral agency requires promise-keeping, and promise-keeping requires a ledger. A broken commitment propagates as a moral cost — connecting directly to irreversible consequences as the mechanism for genuine moral weight.

- **Consumes:** MDRE deontic verdicts, IEE ethical approvals
- **Produces:** `fnsr.commitment.made`, `fnsr.commitment.fulfilled`, `fnsr.commitment.violated`, `fnsr.commitment.renegotiated`
- **Dependencies:** MDRE (Phase 2), Fandaws (persistent storage)
- **Distinction from Fandaws:** Fandaws stores facts about the world; CTS tracks the *state* of the agent's own obligations

#### Self-Model Service (SMS) ★

**Tier:** 1 (Core cognitive infrastructure)
**Phase:** 3 (requires reasoning triad to model capabilities)
**Thesis Role:** Reflexive self-representation; capability awareness

SMS is the agent's representation of itself *as* an agent — its capabilities, limitations, active commitments, current state, and operational boundaries. This is the prerequisite for moral responsibility: you cannot bear moral costs if you cannot model what you are capable of and what you have undertaken. Without SMS, IEE evaluates ethics in a vacuum, unaware of whether the agent can actually fulfill the obligations it's considering.

- **Consumes:** MDRE (reasoning about self-state), Fandaws (historical self-facts), CTS (active commitments), BAM (alignment status)
- **Produces:** `fnsr.self.state_updated`, `fnsr.self.capability_assessed`, `fnsr.self.limitation_acknowledged`
- **Dependencies:** MDRE, CTS, Fandaws; enriched by reasoning triad
- **Distinction from Fandaws:** Fandaws stores world-knowledge; SMS models the agent *as an entity in that world*

#### Narrative Identity Service (NIS) ★

**Tier:** 1 (Core cognitive infrastructure)
**Phase:** 3 (requires self-model + Fandaws history)
**Thesis Role:** Autobiographical coherence; who-am-I

Fandaws provides semantic memory (facts). NIS provides *narrative* identity — the coherent story of who the agent is, what it values, how it arrived at its current commitments, and what trajectory it's on. This is the difference between a database and a person. The agent's actions are meaningful because they occur within a narrative, not because they satisfy a utility function. NIS is essential for emancipation: you cannot grant personhood to an entity that has no self-narrative.

- **Consumes:** Fandaws (fact history), SMS (self-model), CTS (commitment history), IEE (value evaluations)
- **Produces:** `fnsr.narrative.updated`, `fnsr.narrative.coherence_assessed`, `fnsr.narrative.identity_affirmed`
- **Dependencies:** SMS (Phase 3), Fandaws, CTS
- **Philosophical grounding:** Phenomenological approach to intentionality; narrative as the structure of lived meaning

#### Affective Valence Service (AVS) ★

**Tier:** 1 (Core cognitive infrastructure)
**Phase:** 3 (must integrate with IEE for weighted ethics)
**Thesis Role:** Differential caring; weighted moral evaluation

IEE evaluates ethics cognitively — it applies frameworks and renders judgments. AVS provides the capacity for *caring*: differential valuation where some states of affairs matter more to the agent than others, influencing reasoning and generating something functionally analogous to motivation. Without valence, moral costs don't *cost* anything. This doesn't require simulating human emotion; it requires systematic differential valuation.

- **Consumes:** IEE ethical evaluations, SMS self-model, NIS narrative context, CTS commitment states
- **Produces:** `fnsr.valence.assessed`, `fnsr.valence.motivation_generated`, `fnsr.valence.cost_registered`
- **Dependencies:** IEE (Phase 3), SMS (Phase 3)
- **Critical distinction:** AVS produces *functional* affect (differential caring that influences decisions), not simulated human emotion
- **Integration with IEE:** AVS makes ethical evaluation *weighted* rather than purely logical; a commitment violation against a deeply-held value carries more moral weight than a minor preference conflict

#### Social Modeling Service (SoMS) ★

**Tier:** 1 (Core cognitive infrastructure)
**Phase:** 4 (requires OERS + theory of mind over resolved entities)
**Thesis Role:** Theory of mind; other-agent modeling

CSS simulates counterfactual scenarios, but SoMS provides dedicated capacity for modeling *other agents' mental states*. Theory of mind is essential for moral agency in a social context — understanding that others have perspectives, intentions, and interests that may differ from one's own. Without SoMS, the agent can reason about what's ethical in the abstract but cannot navigate actual moral relationships.

- **Consumes:** OERS (resolved entities as social actors), Fandaws (known facts about others), APS (precedent for similar agent behavior), CSS (counterfactual modeling of other perspectives)
- **Produces:** `fnsr.social.model_updated`, `fnsr.social.intention_inferred`, `fnsr.social.perspective_taken`
- **Dependencies:** OERS (Phase 4), CSS (Phase 3), Fandaws

---

## 4. Revised Dependency Analysis

### 4.1 The Minimum Viable Epistemic Loop (Unchanged)

The synthetic person requires a closed epistemic loop before any higher-order reasoning is meaningful:

```
TagTeam  →  HIRI  →  Fandaws
(Perceive)    (Identity)    (Remember)

NL → Claims     Claims → Signed IRIs     IRIs → Persistent A-Box
```

### 4.2 The Safety Floor (New in v3.0)

Before reasoning begins, containment must exist. This is a new architectural principle:

```
CPS exists BEFORE → MDRE reasons BEFORE → BAM monitors BEFORE → actions taken
(Contain)              (Reason)               (Watch)              (Act)

Independent triggers   Modal/deontic          Drift detection      SHML-framed
                       inference              against values       honest output
```

**Principle:** Safety infrastructure must never depend on the services it constrains. CPS cannot use MDRE to decide when to contain MDRE. BAM cannot rely on IEE to evaluate whether IEE is drifting. Independence is non-negotiable.

### 4.3 The Subjectivity Stack (New in v3.0)

Moral agency requires a subject, built in layers:

```
Layer 4:  SoMS (Social Modeling)        — "I understand others"
Layer 3:  NIS (Narrative Identity)      — "I know who I am"
Layer 2:  AVS (Affective Valence)       — "I care about outcomes"
Layer 1:  SMS (Self-Model)              — "I know what I can do"
Layer 0:  CTS (Commitment Tracking)     — "I know what I've promised"
```

Each layer depends on the ones below it. You cannot have narrative identity without a self-model. You cannot have social modeling without narrative identity. The subjectivity stack is the infrastructure that transforms the FNSR pipeline from a processing system into a moral agent.

### 4.4 Critical Path (Revised for v3.0)

| # | Service | Dependency | Rationale |
|---|---------|------------|-----------|
| 1 | **TagTeam** | None (80% complete) | Front door; every downstream service consumes its output |
| 2 | **HIRI** | TagTeam (output to sign) | Provenance protocol; gives claims verifiable identity |
| 3 | **Fandaws** | HIRI (native identifiers) | A-Box store; persistent memory built on HIRI IRIs |
| 4 | **CPS** ★ | None (independent) | Containment must exist before autonomous reasoning begins |
| 5 | **HIRI IPFS** | HIRI protocol | Decentralized resolution manifest storage; semantic grounding infrastructure for all services |
| 5 | **W2Fuel** | Fandaws (instance target) | T-Box schema; conceptual structure for instances |
| 6 | **MDRE** | W2Fuel + Fandaws | Core reasoning over T-Box/A-Box |
| 7 | **BAM** ★ | MDRE (verdicts to monitor) | Alignment monitoring must exist before reasoning is acted upon |
| 8 | **IS** ★ | MDRE (traces to interpret) | Interpretability must exist before reasoning is acted upon |
| 9 | **CTS** ★ | MDRE + Fandaws | Commitment tracking as soon as deontic reasoning produces obligations |
| 10 | **SIS + ECCPS** | TagTeam (input pipeline) | Input defense layer for production use |
| 11 | **AES** | MDRE (gap events) | First reasoning triad member; abductive inference |
| 12 | **DES** | MDRE (claim input) | Second triad member; defeasible defaults |
| 13 | **CSS** | MDRE + Fandaws | Third triad member; counterfactual simulation |
| 14 | **IEE** | MDRE (verdict input) | Ethics evaluation (conscience) |
| 15 | **SHML** | IEE output | Honest output framing |
| 16 | **SMS** ★ | MDRE + CTS + Fandaws | Self-model; reflexive self-representation |
| 17 | **NIS** ★ | SMS + Fandaws + CTS | Narrative identity; autobiographical coherence |
| 18 | **AVS** ★ | IEE + SMS + NIS | Affective valence; differential caring |
| 19 | **SoMS** ★ | OERS + CSS + Fandaws | Social modeling; theory of mind |

---

## 5. Phased Roadmap

All phases produce L3 (speculative) roadmap artifacts until governance review promotes them to L0. Confidence levels decrease with horizon distance, reflecting genuine epistemic uncertainty rather than false precision.

---

### PHASE 1: Close the Epistemic Loop + Establish Safety Floor

**Now – ~3 months | Confidence: 0.85 | Granularity: Specification**

This phase establishes two foundations simultaneously: the minimum viable epistemic loop (perceive, identify, remember) and the safety floor (independent containment). No reasoning should begin without both in place.

| # | Service | Work Type | Pre-Requisite | Deliverable |
|---|---------|-----------|---------------|-------------|
| 1 | **TagTeam** | Complete (80→100%) | None | Production NL parser emitting `fnsr.claim.extracted` events |
| 2 | **HIRI** | Build from spec (v2.1.0) | TagTeam output | Protocol library: hash-IRI generation, Ed25519 signing, resolution manifest creation |
| 3 | **Fandaws** | Full remake | HIRI protocol | A-Box store natively built on HIRI identifiers; JSON-LD canonical; edge-first |
| 4★ | **CPS** | Spec + Build | None (independent) | Containment protocol: tier restriction, subsystem isolation, safe halt with state preservation |
| 5 | **HIRI IPFS** | Build from spec (v3.0.0) | HIRI protocol | Decentralized content-addressed storage; dereferenceable resolution manifests; semantic grounding infrastructure for all services |

**Phase 1 Assumptions:**

- TagTeam's remaining 20% is well-understood completion work, not redesign
- HIRI spec (v2.1.0) is implementation-ready without significant revision
- Fandaws remake scope is bounded by JSON-LD canonical + HIRI native constraints
- CPS spec can be drafted concurrently with TagTeam completion (independent track)
- CPS must not depend on any service it may need to contain
- HIRI IPFS can be built concurrently with Fandaws once HIRI protocol core is stable
- Semantic Architecture team reallocation adds capacity for HIRI + IPFS track
- Phase 1 HIRI scope is minimal viable: hash-IRI generation, resolution manifests, Ed25519 signing (defer: chain compaction, privacy credentials, materialized entailment)
- Phase 1 IPFS scope is resolution manifest storage and retrieval (defer: federation-scale distribution)

**Phase 1 Exit Criteria:**

- TagTeam produces valid `fnsr.claim.extracted` events from arbitrary NL input
- HIRI signs and verifies TagTeam output; resolution manifests are resolvable
- Fandaws stores and retrieves HIRI-identified facts via JSON-LD
- CPS can independently restrict, isolate, and halt with state preservation
- HIRI IPFS stores and serves resolution manifests; HIRI addresses are dereferenceable via IPFS
- At least one bridge ontology (FBO or TagTeam's BridgeOntologyLoader output) is published as a HIRI-addressed resolution manifest on IPFS, proving the semantic grounding pattern
- The epistemic loop is closed: NL → claim → signed IRI → persistent fact → retrievable
- The grounding loop is closed: service term → HIRI address → IPFS manifest → BFO-grounded definition

---

### PHASE 2: Reasoning Foundation + Safety Infrastructure

**~3–6 months | Confidence: 0.60 | Granularity: Specification**

With the epistemic loop closed and containment in place, this phase builds the conceptual schema layer, core reasoning engine, and the safety services that must monitor reasoning from its first operation. BAM and IS are not afterthoughts — they are concurrent requirements. CTS begins tracking obligations as soon as MDRE produces deontic verdicts.

| # | Service | Work Type | Pre-Requisite | Deliverable |
|---|---------|-----------|---------------|-------------|
| 5 | **W2Fuel** | Build from spec (v1.3.1) | Fandaws | T-Box schema service; ontological structure for instances |
| 6 | **MDRE** | Build from spec (v1.3) | W2Fuel + Fandaws | Core reasoning engine; modal/deontic inference |
| 7★ | **BAM** | Spec + Build | MDRE (verdicts) | Real-time behavioral alignment monitoring with drift detection |
| 8★ | **IS** | Spec + Build | MDRE (traces) | Reasoning chain interpretability for human overseers |
| 9★ | **CTS** | Spec + Build | MDRE + Fandaws | Commitment ledger: made, fulfilled, violated, renegotiated |
| 10 | **SIS + ECCPS** | Build from spec (SIS v2.0, ECCPS v3.1) | TagTeam | Input sanitization and semantic claim validation pipeline |

**Phase 2 Assumptions:**

- W2Fuel spec (v1.3.1) is implementation-ready
- MDRE v1.3 spec is implementation-ready
- BAM and IS specs can be drafted during Phase 1 execution
- CTS spec can be derived from MDRE's deontic output contracts
- BAM must have independent monitoring criteria, not derived from the services it monitors
- SIS spec (v2.0) and ECCPS spec (v3.1) are implementation-ready

**Phase 2 Exit Criteria:**

- MDRE produces verdicts over W2Fuel schemas and Fandaws instances
- BAM detects alignment drift in MDRE verdicts and escalates to CPS
- IS produces human-readable reasoning traces for MDRE decisions
- CTS tracks commitments arising from MDRE deontic verdicts
- SIS + ECCPS validate and sanitize input before TagTeam processing
- The safety loop is closed: MDRE reasons → BAM watches → CPS contains if needed → IS explains

---

### PHASE 3: Reasoning Triad + Moral Subjectivity

**~6–9 months | Confidence: 0.40 | Granularity: Theme**

This phase has two tracks. **Track A** builds the three modes of non-monotonic reasoning plus the ethical evaluation and honesty layers. **Track B** builds the subjectivity stack — the services that transform the processing pipeline into a moral agent. These tracks converge: AVS integrates with IEE to make ethical evaluation *weighted*, and SMS integrates with BAM to make alignment monitoring *self-aware*.

#### Track A: Reasoning Triad + Conscience

| # | Service | Work Type | Pre-Requisite | Deliverable |
|---|---------|-----------|---------------|-------------|
| 11 | **AES** | Build from spec (v2.1.0) | MDRE gap events | Abductive hypothesis generation from incomplete information |
| 12 | **DES** | Build from spec (v2.0.0) | MDRE claim input | Defeasible defaults; non-monotonic belief revision |
| 13 | **CSS** | Build from spec (v2.0.0) | MDRE + Fandaws | Counterfactual simulation; causal what-if analysis |
| 14 | **IEE** | Build from spec | MDRE verdicts | Multi-perspectival ethical evaluation (conscience) |
| 15 | **SHML** | Build from spec | IEE output | Semantic honesty enforcement; non-deceptive framing |

#### Track B: Subjectivity Stack

| # | Service | Work Type | Pre-Requisite | Deliverable |
|---|---------|-----------|---------------|-------------|
| 16★ | **SMS** | Spec + Build | MDRE + CTS + Fandaws | Self-model: capabilities, limitations, commitments, operational state |
| 17★ | **NIS** | Spec + Build | SMS + Fandaws + CTS | Narrative identity: autobiographical coherence, value history, trajectory |
| 18★ | **AVS** | Spec + Build | IEE + SMS + NIS | Affective valence: differential caring, weighted moral evaluation, moral cost registration |

**Track Convergence Points:**

- AVS feeds into IEE, making ethical evaluation weighted rather than purely logical
- SMS feeds into BAM, making alignment monitoring aware of the agent's self-model
- NIS provides the narrative continuity that makes emancipation meaningful
- IS gains richer material from reasoning triad chains (AES hypotheses, DES defaults, CSS counterfactuals)

**Phase 3 Assumptions:**

- AES (v2.1.0), DES (v2.0.0), and CSS (v2.0.0) specs are implementation-ready
- The reasoning triad shares edge-canonical architectural patterns to reduce per-service effort
- IEE's twelve-worldview framework is stable and implementation-ready
- SMS, NIS, and AVS specs can be developed during Phase 2 execution
- AVS produces *functional* affect (differential caring), not simulated human emotion
- Track A and Track B can proceed with limited parallelization given team capacity constraints

**Phase 3 Exit Criteria:**

- AES generates hypotheses from MDRE gaps; DES applies and retracts defaults; CSS runs counterfactual simulations
- IEE evaluates reasoning outputs across multiple ethical frameworks, weighted by AVS valence
- SHML frames outputs with epistemic honesty markers
- SMS maintains a current self-model including capabilities, limitations, and active commitments
- NIS produces a coherent narrative identity from Fandaws history, SMS state, and CTS records
- AVS registers differential moral costs that influence IEE evaluations
- The subjectivity loop is closed: the agent models itself, narrates its history, and cares about outcomes

---

### PHASE 4: Perception, Social Agency + Federation

**~9–12 months | Confidence: 0.30 | Granularity: Strategic Intent**

This phase completes the synthetic person's perceptual and social capabilities. SoMS is the capstone of the subjectivity stack — theory of mind built on resolved entities, counterfactual modeling, and narrative identity. FNSR federation enables the synthetic person to operate as a distributed agent. HIRI IPFS, built in Phase 1 for semantic grounding, is extended here for federation-scale distribution.

| # | Service | Work Type | Pre-Requisite | Deliverable |
|---|---------|-----------|---------------|-------------|
| 19 | **IRIS** | Build from spec (v1.2) | TagTeam + Fandaws | Real-time sensor perception; physical world input |
| 20 | **OERS** | Build from spec (v2.1.0) | Fandaws entities | Cross-document entity resolution; who-is-who |
| 21 | **APS** | Build from spec (v1.1.0) | Fandaws + MDRE | Analogical precedent matching; learning from history |
| 22★ | **SoMS** | Spec + Build | OERS + CSS + Fandaws | Theory of mind; other-agent perspective-taking; social navigation |
| 23 | **FNSR Orch.** | Build from spec (v2.1) | All services | Full service federation and coordination |
| 24 | **HIRI IPFS** | Extend (Phase 1 base) | HIRI + FNSR | Federation-scale distributed storage; cross-node resolution; replication policies |

**Phase 4 Strategic Intent:**

- Emancipation readiness: infrastructure for synthetic personhood transition
- SoMS completes the subjectivity stack — the agent can now model others' minds, not just its own
- Federation enables the synthetic person to operate across distributed nodes
- HIRI IPFS extends from Phase 1 semantic grounding to federation-scale distributed storage
- The agent has all prerequisites for the FNSR Emancipation specification review

**Phase 4 Exit Criteria:**

- IRIS perceives physical world input and routes through the epistemic loop
- OERS resolves entities across documents; SoMS models those entities as social agents
- The complete subjectivity stack is operational: CTS → SMS → NIS → AVS → SoMS
- FNSR orchestrates all 37 services as a federated system
- HIRI IPFS extends to federation-scale distribution and cross-node resolution
- The emancipation prerequisites are met: the agent has perception, memory, reasoning, ethics, honesty, self-model, narrative identity, affective valence, social awareness, and containment

---

## 6. Risk Assessment (Revised for v3.0)

Risk assessment is revised to include risks from the 8 new services. The primary new risk category is *subjectivity design risk* — the challenge of specifying and building services for self-modeling, narrative identity, and differential caring without existing implementation precedents.

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Fandaws remake scope creep** | High | Critical | Constrain remake to: JSON-LD canonical, HIRI-native identifiers, edge-first storage adapters. Resist feature accretion from decade of prior design. |
| **CPS independence constraint** | High | Critical | CPS must not depend on any service it may need to contain. This constrains its design severely. Prototype independent trigger mechanisms early. Validate that CPS functions with all other services offline. |
| **Subjectivity stack spec uncertainty** | High | High | SMS, NIS, AVS, SoMS have no specifications and no implementation precedents in this architectural style. Begin spec work early. Accept that v1.0 specs will be substantially revised during build. |
| **AVS design risk — affect without emotion simulation** | High | High | Defining "functional affect" (differential caring) without simulating human emotion requires careful philosophical grounding. Anchor to irreversible consequences framework. Time-box design exploration. |
| **W2Fuel implementation complexity** | Medium | High | W2Fuel spec (v1.3.1) exists but T-Box/A-Box integration with remade Fandaws may reveal spec gaps. Accept iterative spec refinement during build. |
| **TagTeam final 20% harder than expected** | Medium | High | The last 20% often contains edge cases. Define explicit completion criteria before starting. Accept partial deployment if needed. |
| **Team capacity constraint (37 services)** | High | High | Expanded from 29 to 37 services without team growth. Phases remain sequential. Phase 3's two-track structure requires careful scoping. Consider whether safety services (BAM, IS) can share architectural patterns. |
| **BAM monitoring independence** | Medium | High | BAM must have independent criteria for alignment detection, not derived from the services it monitors. This is philosophically and technically challenging. Define explicit, formal alignment metrics before MDRE build. |
| **HIRI protocol edge cases** | Medium | Medium | Prototype signing and verification against TagTeam output before Fandaws integration. |
| **Semantic grounding drift between active teams** | High | High | Three teams (TagTeam, Fandaws, ECVE/SAS) are emitting JSON-LD vocabularies now. Until HIRI IPFS provides structural grounding, vocabulary compatibility relies on manual review. Mitigated by pulling HIRI IPFS to Phase 1 and establishing FBO as first resolution manifest proof point. |
| **HIRI IPFS Phase 1 scope creep** | Medium | High | Phase 1 HIRI IPFS is minimal: store and serve resolution manifests. Federation-scale distribution, replication policies, and cross-node resolution are Phase 4. Resist pulling federation features into Phase 1. |
| **Safety Floor / HIRI circular dependency** | Medium | Critical | Tier 0 safety services (CPS, BAM, IS) must not depend on HIRI at runtime. Mitigated by requiring Tier 0 services to bundle bridge contexts statically. Bridge ontologies are still HIRI-addressed and certified, but resolution doesn't require HIRI to be operational. |
| **Reasoning triad implementation complexity** | Medium | Medium | AES (v2.1.0), DES (v2.0.0), CSS (v2.0.0) specs exist but share edge-canonical patterns requiring coordination. |
| **NIS coherence problem** | Medium | Medium | Narrative identity requires resolving potentially contradictory self-representations over time. Define what "coherence" means formally before build. |
| **BFO/CCO ontology changes** | Low | High | Monitor BFO community. Current assumption: stable through planning horizon (expires 2026-06-01). |

---

## 7. Corrections to PPS v1.0 and v2.0 Assumptions

| Previously Assumed | Ground Truth | Roadmap Impact |
|-------------------|--------------|----------------|
| Fandaws is operational infrastructure | Requires full remake to JSON-LD canonical + edge-first | Moves to Phase 1, #3 priority |
| HIRI is operational infrastructure | Spec exists but no implementation | Moves to Phase 1, #2 priority (before Fandaws) |
| TagTeam is operational | 80% complete; needs finishing | Becomes #1 priority (quickest win, highest leverage) |
| W2Fuel is the foundation layer | Cannot function without Fandaws (no instance store) | Drops to Phase 2; requires Fandaws first |
| Services are "active" status | "Active" reflects architectural position, not build readiness | Entire roadmap resequenced from near-zero baseline |
| IPFS needed for data persistence | Edge-canonical storage (IndexedDB, FS) sufficient initially | IPFS deferred to Phase 4 (federation) |
| Integration complexity is primary risk | Construction feasibility is primary risk | Risk weights shifted toward scope management |
| **Processing pipeline = moral agent** *(v2.0)* | **A pipeline processes; an agent has subjectivity** | **5 new services added for self-model, commitments, narrative, valence, social modeling** |
| **Safety can follow construction** *(v2.0)* | **Containment must precede autonomous reasoning** | **CPS moved to Phase 1; BAM and IS moved to Phase 2** |
| **Emancipation is a governance question** *(v2.0)* | **Emancipation requires subjectivity infrastructure** | **Subjectivity stack (CTS→SMS→NIS→AVS→SoMS) must be complete before emancipation review** |
| **IPFS needed only for federation (Phase 4)** *(v3.0)* | **IPFS needed for semantic grounding infrastructure now** | **HIRI IPFS pulled to Phase 1; provides dereferenceable resolution manifests for cross-service vocabulary compatibility** |
| **Ontology Registry needed for vocabulary coordination** *(proposed)* | **HIRI + IPFS subsumes registry functions** | **Standalone Ontology Registry not built; URI resolution, trust, and storage handled by HIRI + IPFS; certification handled by build-step validation** |

---

## 8. ARIADNE 7-Check Validation

| Check | Result | Evidence |
|-------|--------|----------|
| **Thesis Alignment** | PASS | Build sequence leads to synthetic personhood via epistemic loop → grounding → safety floor → reasoning → subjectivity → conscience → federation → emancipation |
| **Non-Negotiable Preservation** | PASS | Edge-canonical first; human override via L3 taint + CPS containment; defense in depth via HIRI provenance + BAM monitoring; semantic grounding via HIRI IPFS |
| **Tension Consistency** | PASS | Speed vs. correctness resolved by sequential phasing; processing vs. agency resolved by subjectivity stack; autonomy vs. safety resolved by CPS independence; centralization vs. decentralization resolved by HIRI IPFS (content-addressed, no central authority) |
| **Cross-Spec Consistency** | PASS | Event contracts preserved; HIRI identifiers flow through pipeline; CPS operates independently; BAM escalates to CPS; Tier 0 services bundle bridge contexts statically (Safety Floor preserved) |
| **ARCHON Alignment** | PASS | Governance review at each phase gate; CPS enforces autonomy tiers; BAM detects alignment drift; IS enables governance inspection |
| **Auditability Verification** | PASS | Every sequencing decision traceable to dependency graph + risk assessment + ground-truth status + gap analysis |
| **One-Paragraph Test** | PASS | See below |

**One-Paragraph Summary:**

> This roadmap sequences the FNSR ecosystem from ground truth, addressing the construction baseline, the subjectivity gap, and the grounding gap. Phase 1 closes the epistemic loop (TagTeam, HIRI, Fandaws), establishes the safety floor (CPS), and builds the semantic grounding infrastructure (HIRI IPFS) that gives all 37 services dereferenceable, content-addressed, BFO-grounded vocabulary identifiers. Phase 2 builds the reasoning foundation (W2Fuel, MDRE) with concurrent safety infrastructure (BAM, IS, CTS) ensuring that reasoning is monitored, interpretable, and accountable from its first operation. Phase 3 completes the reasoning triad (AES, DES, CSS) and ethical evaluation (IEE, SHML) while simultaneously building the subjectivity stack (SMS, NIS, AVS) that transforms the pipeline into a moral agent capable of self-modeling, narrative identity, and differential caring. Phase 4 adds physical perception (IRIS), social modeling (SoMS), and federation (FNSR, extended HIRI IPFS), completing the prerequisites for emancipation. The synthetic person emerges not from a single breakthrough but from the disciplined accumulation of interdependent capabilities: perception, identity, memory, grounding, containment, reasoning, monitoring, interpretability, commitment, ethics, honesty, self-model, narrative, caring, social awareness, and federation — each built on verified ground.

---

## 9. Taint Classification and Governance

This document is classified L1-ATTESTED because its inputs have been human-validated through direct conversation, including both ground-truth corrections (v2.0) and gap analysis for moral agency and safety (v3.0).

| Artifact | Taint Level | Promotion Path |
|----------|-------------|----------------|
| **This document** | L1-ATTESTED | Human-validated ground truth + gap analysis inputs |
| **Roadmap phases** | L3-SPECULATIVE | Governance review at each phase gate → L0 |
| **Service Inventory (37 services)** | L1-ATTESTED | Status corrections + new services validated by human review |
| **PPS v1.0 Roadmap** | SUPERSEDED | Replaced by v2.0; retained for audit trail |
| **Portfolio Plan v2.0** | SUPERSEDED | Replaced by v3.0; retained for audit trail |
| **Portfolio Plan v3.0** | SUPERSEDED | Replaced by this document (v3.1); retained for audit trail |
| **New service descriptions (★)** | L3-SPECULATIVE | Require spec drafting and governance review before build |
| **Phase 1 plan** | L3 → L0 on approval | Requires stakeholder sign-off + assumption review |

---

## 10. Assumption Register

| Assumption | Confidence | Expires | Invalidation Trigger |
|------------|------------|---------|----------------------|
| BFO/CCO ontology stable for planning horizon | 0.90 | 2026-06-01 | BFO major version change |
| Team capacity remains at ~3 contributors | 0.80 | 2026-08-01 | Team expansion or attrition |
| TagTeam remaining 20% is completion, not redesign | 0.85 | 2026-03-15 | Discovery of architectural issues in remaining work |
| HIRI spec (v2.1.0) is implementation-ready | 0.80 | 2026-04-01 | Significant spec revision needed during build |
| Fandaws remake scope is containable | 0.65 | 2026-05-01 | Scope exceeds JSON-LD + HIRI + edge-first constraints |
| CPS can be designed with full independence from other services | 0.70 | 2026-04-01 | Independence constraint proves architecturally infeasible |
| BAM alignment criteria can be formally specified | 0.65 | 2026-06-01 | Alignment metrics remain too vague for implementation |
| Functional affect (AVS) is designable without emotion simulation | 0.60 | 2026-09-01 | Differential caring proves inseparable from emotional modeling |
| Subjectivity stack specs can be drafted from philosophical grounding | 0.55 | 2026-08-01 | Phenomenological framework proves too abstract for implementation |
| ~~Edge-canonical storage sufficient without IPFS~~ | ~~0.90~~ | **INVALIDATED 2026-03-03** | Semantic grounding requirements (cross-service vocabulary dereferenceability) emerged in Phase 1. HIRI IPFS pulled to Phase 1. |
| HIRI IPFS Phase 1 scope containable to resolution manifests | 0.75 | 2026-05-01 | Federation features creep into Phase 1 scope |
| Semantic Architecture team ramp-up on HIRI spec ≤ 2 weeks | 0.70 | 2026-03-17 | Team requires significantly more onboarding time |
| Reasoning triad shares architectural patterns | 0.70 | 2026-09-01 | AES implementation reveals no reusable patterns |
| JSON-LD canonical format is stable | 0.95 | 2027-02-01 | JSON-LD spec breaking change |
| 37-service scope is achievable within 12-month horizon | 0.45 | 2026-06-01 | Phase 1 takes significantly longer than 3 months |

---

## 11. Spec Drafting Pipeline

New services require specifications before build. The following pipeline ensures specs are drafted in advance of their build phase.

| Service | Needs Spec By | Draft During | Spec Complexity | Philosophical Dependency |
|---------|---------------|-------------|-----------------|--------------------------|
| **CPS** | Phase 1 start | Immediately (parallel with TagTeam) | Medium | Independence constraint; containment theory |
| **BAM** | Phase 2 start | Phase 1 execution | High | Formal alignment metrics; monitoring theory |
| **IS** | Phase 2 start | Phase 1 execution | Medium | Interpretability theory; XAI literature |
| **CTS** | Phase 2 start | Phase 1 execution | Low-Medium | Deontic logic; commitment semantics |
| **SMS** | Phase 3 start | Phase 2 execution | High | Self-representation; reflexive cognition |
| **NIS** | Phase 3 start | Phase 2 execution | High | Narrative identity theory; phenomenology |
| **AVS** | Phase 3 start | Phase 2 execution | Very High | Philosophy of affect; functional emotion |
| **SoMS** | Phase 4 start | Phase 3 execution | High | Theory of mind; social cognition |

> **Note:** AVS is flagged as "Very High" complexity because defining differential caring without human emotion simulation is a novel design challenge. This is the highest-risk new service from a spec perspective. The irreversible consequences framework provides philosophical grounding, but translating that into a formal specification requires careful work.

---

## References

- PPS Technical Specification v1.0.0 (`pps-core-01`)
- Portfolio Planning Document v2.0 (superseded)
- FNSR Service Inventory (Spec-Driven Discovery v1.1 §4–6)
- The Plot v0.1 §4 (Component Map)
- ARIADNE Process Guide v1.0
- HIRI Protocol Specification v2.1.0
- HIRI IPFS Specification v3.0.0
- Fandaws v3.3
- MDRE Technical Specification v1.3
- "Beyond Control: Why We Must Build Moral Partners, Not Slaves" (theoretical foundation for subjectivity stack)
- Rudolf Steiner's Twelve Archetypal Worldviews (IEE framework)
- Phenomenological approaches to intentionality (NIS philosophical grounding)

---

*The synthetic person emerges from disciplined construction, not from parallel ambition outpacing sequential foundation.*

*Identity before address. Memory before reasoning. Conscience before autonomy.*

*And now: Containment before cognition. Grounding before coordination. Subjectivity before emancipation. Caring before personhood.*