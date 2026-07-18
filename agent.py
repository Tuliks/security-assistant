"""The security assistant — the whole agent, in one readable file.

Same shape as single-agent-lab/agent.py: an LLM, a set of tools, a typed union
output, and a bound on the loop. Pydantic AI runs the ReAct loop internally
(Thought -> tool call -> Observation -> repeat -> typed output); trace.py makes
that loop visible.

    agent = LLM + tools + loop
            (model) (below) (Pydantic AI runs it)

Provider-agnostic: set AGENT_MODEL / the matching API key in .env.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv
from pydantic_ai import Agent, ModelRetry, RunContext
from pydantic_ai.usage import UsageLimits

load_dotenv()  # pull OPENAI_API_KEY / ANTHROPIC_API_KEY / AGENT_MODEL from .env

from schemas import NeedMoreInfo, SecurityAnswer
from tools.analytics import average_cvss, calculate_risk, count_critical, extract_cves
from tools.cve_lookup import cve_lookup
from tools.rag_search import rag_search
from tools.remediation import suggest_remediation

# OpenAI by default (matches the other labs). Swap to e.g. "openai:gpt-5.1" or
# "anthropic:claude-opus-4-8" via AGENT_MODEL — Pydantic AI reads the key from env.
MODEL = os.getenv("AGENT_MODEL", "openai:gpt-4.1")

SYSTEM_PROMPT = """\
You are a security analyst assistant. Security engineers upload scanner reports
(Gitleaks, Trivy, Nessus, ...) and ask you to investigate: find issues, count
and prioritize them, enrich CVEs with external intelligence, and suggest fixes.

How to work:
- To learn WHAT findings exist, call rag_search. Cite the findings you use; never
  invent a finding, an asset name, or a CVE that rag_search didn't return.
- For counts and averages, use the analytics tools (count_critical, average_cvss)
  rather than eyeballing — they are exact.
- For anything about a specific CVE (its real CVSS, severity, known-exploited/KEV
  status, affected versions, patch guidance), call cve_lookup. Do NOT state a
  CVSS score or KEV status from memory — those are authoritative facts you must
  fetch. Use extract_cves to pull ids out of text first if needed.
- To prioritize, feed the fetched CVSS (and KEV/exposure context) into
  calculate_risk — don't guess the score yourself.
- For fixes, call suggest_remediation with the finding's category.

Grounding rule (the one thing you must NOT do): decide WHICH findings/CVEs to
investigate freely, but never fabricate CVSS scores, KEV status, counts, or
remediation from your weights. Every such fact must come from a tool result.

When you have grounded findings, return a SecurityAnswer: a clear analyst-style
message, the findings you cited, any CVE ids, and the tools you used. Populate
summary_data with key numbers when relevant (e.g. {"critical": 3}).

Return NeedMoreInfo instead when the reports contain nothing relevant, the
question is out of scope, or you genuinely can't ground an answer — ask, don't
hallucinate. Follow-up questions may rely on earlier turns; use that context.
"""

# One LLM, one typed output that is a UNION (answer, or abstain and ask).
agent = Agent(
    MODEL,
    output_type=[SecurityAnswer, NeedMoreInfo],
    system_prompt=SYSTEM_PROMPT,
)

# Tools. Each gets its OWN retry budget: when a tool raises ModelRetry or the
# model sends type-invalid arguments, only that tool's counter advances. This is
# separate from the run-wide UsageLimits below. All are plain (no RunContext),
# so we register with tool_plain — same idiom as the travel lab.
agent.tool_plain(retries=2)(rag_search)
agent.tool_plain(retries=1)(count_critical)
agent.tool_plain(retries=1)(average_cvss)
agent.tool_plain(retries=1)(extract_cves)
agent.tool_plain(retries=1)(calculate_risk)
agent.tool_plain(retries=2)(cve_lookup)
agent.tool_plain(retries=1)(suggest_remediation)

# Guardrail: bound the loop. UsageLimits caps TOTAL work in a single run so an
# investigation can't spiral into dozens of tool calls. A bit higher than the
# travel lab (6) because security questions legitimately chain more tools.
LIMITS = UsageLimits(request_limit=8)


@agent.output_validator
def answer_is_grounded(ctx: RunContext, output: SecurityAnswer | NeedMoreInfo):
    """Output-side business-logic validation — the twin of ModelRetry-in-a-tool.

    Schema validation already guaranteed the shape. This checks things a type
    can't: an answer must actually say something, and it must have called a tool
    (findings and facts come from tools, not the model's weights). Raising
    ModelRetry sends the model back around with the reason.
    """
    if isinstance(output, SecurityAnswer):
        if len(output.message.strip()) < 15:
            raise ModelRetry("The answer is too short to be useful — summarize what the tools returned.")
        if not output.tools_used:
            raise ModelRetry(
                "You returned an answer with no tools_used. Ground it: call rag_search / analytics / "
                "cve_lookup first, or return NeedMoreInfo if nothing supports an answer."
            )
    return output
