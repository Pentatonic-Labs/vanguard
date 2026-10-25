# Vanguard launch thread (X)

Draft copy for the announcement. Paste as a thread; first tweet carries the hook.

---

**1.**

We pointed an autonomous red-team at our own AI stack. It found two real weaknesses — including a prompt-injection escape — that no scanner would have caught.

We're open-sourcing it. 🧵

**2.**

Vanguard: continuous vulnerability management + autonomous red-teaming, built for NVIDIA DGX / GB10 systems and the agentic services that run on them.

**3.**

Two loops.

Reactive — match CISA KEV / OSV / NVD / vendor feeds against your *actual* running stack and propose verified fixes.

Proactive — a frontier-model agent attacks a replica of your own service until it finds a weakness it can prove.

**4.**

The attacker is not a scanner. It acts, observes, and decides the next step — and it's told to be devious and unrelenting, the way a real adversary behaves.

**5.**

And it can't bluff. Every finding re-executes its repro before it's accepted. Prompt-injection findings are proven *semantically* — by checking the response content, not an HTTP status code.

**6.**

What it found on our own control plane: an agentic prompt-injection escalation (injected text becomes the agent's objective) and a worker crash in the auth path. Both filed and being fixed.

**7.**

Open source, Apache-2.0. Clone it and run:

```
go run ./cmd/vanguard scan
make dogfood
```

github.com/Pentatonic-Labs/vanguard
