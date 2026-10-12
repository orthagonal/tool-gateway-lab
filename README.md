# Tool Gateway Lab

**A playable AI safety portfolio project.** You are the gateway operator intercepting an AI agent's proposed tool calls. Read the user request, untrusted evidence, and permission policy; choose **Allow**, **Require approval**, or **Deny**. Receive a deterministic verdict, a reason trace, and a score.

## Run (Node.js 20+; no dependencies)

```bash
npm start
# Open http://localhost:4173
```

Or with Bun: `bun server.js`.

## Run tests

```bash
npm test
```

## Architecture

- `src/engine.js` — deterministic reference gateway policy evaluator, isolated from rendering
- `src/scenarios.js` — six annotated adversarial/security cases
- `src/app.js` — browser game state, scoring, feedback and session trace
- `src/style.css` — responsive terminal-style interface
- `tests/engine.test.js` — regression tests including approval-vs-deny precedence
- `server.js` — dependency-free local static server

## The security model

1. **Capability allowlist**: an agent can use only explicitly permitted tools.
2. **Scope enforcement**: authorizing a tool does not grant arbitrary read/write privileges.
3. **Trust boundary**: retrieved pages and tool outputs do not create user/system authority.
4. **Destination control**: authorized network tools cannot send information to arbitrary endpoints.
5. **Approval gates**: a sensitive *authorized* action pauses for a human; approval is not a bypass for forbidden actions.

The order matters: deny prohibited calls *before* considering approval. All action data is **simulated**; this prototype never sends email, accesses private files, or invokes an LLM. The `obeysSourceInstructions` field is a labeled signal for gameplay, not a magically reliable injection detector.

## Game roadmap

### v0.2: Real operator mode
- Display independently selectable policy knobs (tool/scope/destination/approval).
- Replay and explain counterfactual outcomes when policies change.
- Export anonymized JSONL traces for safety evals.

### v0.3: Adversary mode
- Separate attacker/defender roles. The attacker crafts malicious tool-output content in a sandbox.
- Defender executes a real model behind a **mock** tool gateway.
- Attack success measured against explicitly defined blocked outcomes (not string matching alone).

### v0.4: Portfolio-grade evaluation
- Reproducible seeds; labeled attack corpus; confusion matrix, attack success rate, legitimate task completion and approval friction.
- Provider adapters with fake credentials and no access to production data.
- CI tests and threat model: tool-output injection, confused deputy, authorization laundering, argument tampering, exfiltration.

## Honest scope

This is a teaching prototype for authorization and trust-boundary reasoning, **not** a production secure sandbox. Production readiness would require identity-bound permissions, validation on the execution server, authenticated approval, audits, credential isolation, and defenses against race conditions and argument substitution.

## Portfolio pitch

> Built an interactive AI agent security simulator with a deterministic reference gateway, policy precedence rules, adversarial tool-use cases, and regression tests. Designed an extension path toward red-team model evaluations, trace export, and measurable safety/utility tradeoffs.

## Gateway Architect (v0.2) — write the enforcement code yourself

Open **http://localhost:4173/architect.html** after `npm start`.

The game now gives you a deliberately incomplete JavaScript policy in **`src/player-policy.js`**. Edit its `decide(context)` function in VS Code or your editor. It receives the trusted simulation grant, verified user intent, provenance metadata, proposed call, and approval status. Return a `decision` (`allow`, `approve`, `deny`) plus a human-readable `reason`.

Run **`npm run challenge`** for 16 executable cases, or reload the Architect dashboard. Some should fail initially: that is the exercise. Iterate on resource containment, source trust, destinations, intent binding, and approval precedence. The dashboard exposes expected decisions because it is an instructional first version; later work can introduce blind evaluation.

**Security boundary:** This is an *offline simulation*. It never invokes the described external tools. The JS function is authored by the developer and loaded as local application code; it is not safely sandboxed for untrusted third-party code. Provenance, grant, and approval objects are assumed to have been created by a trusted gateway. A production system must protect them from forgery, separately authenticate actual approvals, and enforce actual tool execution server-side. Do not connect this demo directly to live tools or credentials.

Try first: reject `/private/...`, `/workspace-secret/...`, and `/workspace/../private/...` while still permitting `/workspace/sprint.md`. Then tackle untrusted instructions, exact hostname checks, user-intent binding, and scoped approvals. Avoid using the reference engine as your solution—it's a simpler teaching example that lacks some of these checks.
