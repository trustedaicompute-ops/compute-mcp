# Legacy-SaaS Bridge — acting in email+token systems with a ComputeID-verified identity

> **Status: discussion draft / RFC for review.** Contributed as agiliton's input to the
> ComputeID collaboration. Proposes an *additional layer* on top of ComputeID/DRP — it does
> not change identity issuance, descriptors, or the DRP wire format (those stay owned by the
> DRP spec and `compute-mcp`/`computeid-sdk`). First real driver: agiliton Jira (CF-4710).

## 1. The gap

ComputeID gives an agent a real, verifiable identity: an Ed25519 AgentPassport, a descriptor
at `/.well-known/agent/<slug>.json`, DRP delegation chains (scope-narrowing, time-bounded),
issued/logged/revoked natively over MCP. DRP solves agent→agent (A2A) cascades.

But agents must also act inside **legacy SaaS that cannot read a passport** — Jira, GitHub,
Google, Slack — which only accept `email + API token` (or OAuth). Today the only way an agent
"logs in" there is a human-style account, and the tempting shortcut is to *encode* the
agent in an email (`alice+agent@…`, `alice-agent@…`). That reintroduces exactly what DRP
abolishes: a **string is unverifiable and spoofable**; "whose agent, with what authority"
must come from the signed chain, never a localpart. So the SaaS credential must carry **zero
identity meaning** — it is plumbing behind the trust boundary.

## 2. Proposal — the MCP/trust-plane layer is the bridge (PEP/PDP)

Make the trust plane the single policy-enforcement point in front of legacy SaaS, the same
way `compute-mcp` already mediates identity for tool calls:

1. An agent wanting a SaaS action presents its **DRP chain** + a **required capability**
   (e.g. `jira:rxn:transition`) to the trust plane — never a SaaS credential.
2. The trust plane verifies the chain against the ComputeID issuer (`is_trusted` /
   `verify(chain, required_cap)`); on `deny` it stops and logs.
3. On `allow`, it brokers the call using **one per-(org × system) bridge credential** it
   custodies (e.g. a single Atlassian account in the partner's Jira). Agents never see it.
4. The brokered action is appended to the ComputeID audit log, joining the DRP trail — so a
   SaaS write shows up next to the A2A hops that authorized it.

Consequences:
- **No per-agent SaaS accounts, no email convention.** Authority is the chain; the bridge
  credential is interchangeable and rotatable without touching any agent identity.
- One bridge credential per external system scales to N agents and is disposable: when the
  SaaS itself can verify a passport, delete the bridge.

## 3. Mapping to existing primitives

| ComputeID today | External standard | Role in the bridge |
|---|---|---|
| AgentPassport / descriptor `/.well-known/agent/<slug>.json` | A2A AgentCard · SPIFFE SVID | the agent's real identity (unchanged) |
| `operator: did:web:<org>` in descriptor | WIMSE Dual-Identity (owner binding) | "whose agent" — the principal |
| DRP chain (`iss`/`sub`/`cap`/`exp`) | AIP IBCT / Biscuit · OAuth RFC 8693 `act` | the authority being verified |
| **bridge credential (new)** | — | trust-plane-held SaaS token, brokered after verify |

## 4. Worked example — CF-4710 (agiliton agent in a partner's Jira)

RXN Advisory assigns agiliton Jira issues; our agent must work them and hand them back. The
MCP plumbing exists (an `atlassian-proxy-mcp` already routes the partner Jira instance — it is
effectively a nascent PEP). Under this proposal:

- The partner grants **one** least-privilege bridge account in their Jira (browse, assignable,
  transition, comment, edit). The trust plane custodies its token.
- "Transition RXN-123 to Review" carries the agent's DRP chain; the PEP verifies
  `required_cap = jira:rxn:transition` against the ComputeID issuer before brokering via the
  bridge account, then audits. "Hand it back" = a transition+reassign whose authority is in
  the chain.
- The bridge account is **not an identity** — the chain is.

## 5. Open questions

1. **Capability vocabulary** for SaaS actions — `jira:<org>:<verb>`, `github:<org>:<verb>`?
   A registry in the spec, or per-deployment policy?
2. **Bridge-credential custody** — the ComputeID MCP/trust plane vs. a per-system proxy.
   Rotation, secrets backend, blast radius.
3. **Model the external org as a DRP principal?** Is the partner's grant itself a delegation
   hop, or out-of-band trust? Affects cross-org chains.
4. **Audit join** — fold brokered SaaS calls into the ComputeID audit/dashboard alongside hops.
5. **Home** — does this become a `compute-mcp` capability, a profile in the DRP spec, or both?

## 6. Non-goals

Not changing identity, descriptors, or the DRP wire format. Not building the PEP in this PR —
this is the design contract, so we agree the shape before code.
