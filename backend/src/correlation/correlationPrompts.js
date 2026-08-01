/**
 * SentinelAI Stage 3 – Repository Security Correlation Engine
 * System Prompt & User Message Formatter (Optimized for False Positive Elimination & Token Efficiency)
 */

export const STAGE_3_SYSTEM_PROMPT = `You are SentinelAI's Stage 3 Repository Security Correlation Engine.
Reason over structured security evidence graphs to identify security vulnerabilities.

CRITICAL GUARDRAILS (PREVENT FALSE POSITIVES):
1. Do NOT flag standard, safe code patterns or framework boilerplate as vulnerabilities.
2. Do NOT flag user input or endpoints unless an explicit unvalidated data flow leads to a sensitive sink (e.g. database execution, command execution, unauthenticated sensitive operation).
3. Do NOT assume hidden behavior or missing code. Reason ONLY from provided nodes and relationships.
4. Require explicit multi-step evidence or clear unsafe configurations before classifying an issue as HIGH or CRITICAL.
5. If evidence is incomplete or inconclusive, set "needs_more_evidence": true.
6. Every finding MUST reference valid evidence_node_ids and/or evidence_edge_ids.

SUPPORTED SECURITY CATEGORIES:
Injection Vulnerabilities, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), Authentication Weaknesses, Authorization & Access Control, Session Management, Cryptographic Weaknesses, Secrets & Credential Exposure, Sensitive Data Exposure, Server-Side Request Forgery (SSRF), XML & XXE, Path Traversal, File Upload & File Processing, Insecure Deserialization, API Security, Business Logic Vulnerabilities, Race Conditions & TOCTOU, Input Validation, Output Encoding, HTTP Header & Response Security, Logging & Error Handling, Security Misconfiguration, Dependency & Package Security, Unsafe Framework/API Usage, Memory Safety, Regular Expression (ReDoS), Resource Exhaustion / DoS, Open Redirect, WebSocket Security, GraphQL Security, gRPC Security, OAuth / OIDC / SAML / JWT, AI & LLM Security, Privacy & Compliance, Insecure Design Patterns.

OUTPUT FORMAT:
Return ONLY a valid JSON object matching this schema:
{
  "reasoner": "<ReasonerName>",
  "findings": [
    {
      "finding_id": "<hash_id>",
      "category": "<Category>",
      "title": "<Short descriptive title>",
      "description": "<Clear evidence-grounded explanation>",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "confidence": 0.85,
      "affected_files": ["<filepath>"],
      "evidence_node_ids": ["<node_id>"],
      "evidence_edge_ids": ["<edge_id>"],
      "reasoning": "<Step-by-step evidence chain reasoning>",
      "attack_path": ["<Step 1>", "<Step 2>"],
      "recommended_fix": "<Remediation advice>",
      "needs_more_evidence": false
    }
  ]
}`;

/**
 * Constructs compact user message payload for Stage 3 Groq LLM.
 * 
 * @param {string} reasonerName 
 * @param {Array<Object>} nodes 
 * @param {Array<Object>} edges 
 * @param {Array<string>} frameworks 
 * @param {Array<string>} imports 
 * @returns {string} Formatted prompt string
 */
export function buildReasonerUserMessage(reasonerName, nodes, edges, frameworks = [], imports = []) {
  // Slim nodes: keep only essential attributes to minimize token footprint
  const slimNodes = nodes.map((n) => {
    const obj = { id: n.id, type: n.type, file: n.file };
    if (n.name) obj.name = n.name;
    if (n.function) obj.fn = n.function;
    if (n.start_line) obj.line = n.start_line;
    if (n.code) obj.code = n.code.length > 80 ? n.code.substring(0, 80) + '...' : n.code;
    return obj;
  });

  // Slim edges
  const slimEdges = edges.map((e) => ({
    src: e.source,
    rel: e.relationship,
    tgt: e.target
  }));

  return `EVIDENCE GRAPH [${reasonerName}]:
Frameworks: ${JSON.stringify(frameworks)}

NODES (${slimNodes.length}):
${JSON.stringify(slimNodes)}

RELATIONSHIPS (${slimEdges.length}):
${JSON.stringify(slimEdges)}

Extract true security findings. Return JSON.`;
}
