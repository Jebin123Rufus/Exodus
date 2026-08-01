import Groq from 'groq-sdk';
import { STAGE_3_SYSTEM_PROMPT, buildReasonerUserMessage } from '../correlationPrompts.js';

// Available API Keys Pool
function getApiKeyPool() {
  const keys = [
    process.env.GROQ_LLAMA_PHASE_3,
    process.env.GROQ_API_KEY,
    process.env.GROQ_LLAMA_PHASE_2
  ].filter((k) => typeof k === 'string' && k.trim().length > 10);
  return [...new Set(keys)];
}

/**
 * Parses the retry-after seconds from a Groq 429 error message.
 * Returns 0 if not found or parsing fails.
 */
function parseRetryAfterMs(errMessage) {
  if (!errMessage) return 0;
  const match = errMessage.match(/try again in\s+((?:\d+h)?(?:\d+m)?(?:[\d.]+s)?)/i);
  if (!match) return 0;
  const raw = match[1];
  let totalMs = 0;
  const h = raw.match(/(\d+)h/); if (h) totalMs += parseInt(h[1]) * 3600000;
  const m = raw.match(/(\d+)m/); if (m) totalMs += parseInt(m[1]) * 60000;
  const s = raw.match(/([\d.]+)s/); if (s) totalMs += parseFloat(s[1]) * 1000;
  return Math.min(totalMs, 90000); // cap at 90s
}

// Model Fallback Hierarchy for Groq Rate Limits (429 TPD / TPM)
const MODEL_FALLBACK_LIST = [
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'llama3-8b-8192',
  'mixtral-8x7b-32768'
];

/**
 * Executes a Groq LLM completion with automatic API key rotation and model fallback.
 */
async function callGroqReasonerWithFallback(messages, options = {}) {
  const apiKeys = getApiKeyPool();
  if (apiKeys.length === 0) {
    throw new Error('[BaseReasoner] No Groq API keys found in environment variables!');
  }

  const primaryModel = options.model || 'llama-3.3-70b-versatile';
  const modelsToTry = [primaryModel, ...MODEL_FALLBACK_LIST.filter((m) => m !== primaryModel)];

  let lastError = null;

  for (const modelCandidate of modelsToTry) {
    for (const apiKey of apiKeys) {
      try {
        const groq = new Groq({ apiKey });
        const completion = await groq.chat.completions.create({
          messages,
          model: modelCandidate,
          temperature: options.temperature || 0.1,
          max_completion_tokens: options.max_completion_tokens || 1536,
          response_format: { type: 'json_object' }
        });

        return { completion, modelUsed: modelCandidate };
      } catch (err) {
        lastError = err;
        const isRateLimit = err.status === 429 || (err.message && err.message.includes('rate_limit_exceeded'));
        if (isRateLimit) {
          const retryAfterMs = parseRetryAfterMs(err.message);
          if (retryAfterMs > 0) {
            console.warn(`   ↳ ⚠️ Rate limit (429) on ${modelCandidate} key ...${apiKey.slice(-6)}. Waiting ${(retryAfterMs / 1000).toFixed(1)}s...`);
            await new Promise((r) => setTimeout(r, retryAfterMs));
          } else {
            console.warn(`   ↳ ⚠️ Rate limit (429) on ${modelCandidate} key ...${apiKey.slice(-6)}. Trying next key/model...`);
            await new Promise((r) => setTimeout(r, 300));
          }
          continue;
        } else {
          break;
        }
      }
    }
  }

  throw lastError || new Error('All Groq API keys and models exhausted due to rate limits.');
}

/**
 * Base Class for Domain-Specific Reasoners
 */
export class BaseReasoner {
  constructor(name, targetNodeTypes = []) {
    this.name = name;
    this.targetNodeTypes = targetNodeTypes.map((t) => t.toUpperCase());
  }

  /**
   * Subsets the evidence graph for this reasoner's target domain.
   * @param {EvidenceGraph} graph 
   * @returns {Object} { nodes, edges }
   */
  filterEvidence(graph) {
    const nodes = graph.getNodesByTypes(this.targetNodeTypes);
    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges = graph.getEdgesForNodes(nodeIds);
    return { nodes, edges };
  }

  /**
   * Executes LLM reasoning over domain evidence subset with automatic key rotation and model fallback.
   * @param {EvidenceGraph} graph 
   * @param {Object} [options] 
   * @returns {Promise<Array<Object>>} Array of raw finding objects
   */
  async analyze(graph, options = {}) {
    const { nodes, edges } = this.filterEvidence(graph);

    if (nodes.length === 0) {
      console.log(`   ↳ ℹ️ [${this.name}] 0 relevant nodes found in graph. Skipping execution.`);
      return [];
    }

    console.log(`   ↳ 🧠 [${this.name}] Analyzing ${nodes.length} nodes & ${edges.length} edges...`);

    // Truncate node payload if very large to respect token limits
    const MAX_NODES_PER_CALL = 25;
    let safeNodes = nodes;
    if (nodes.length > MAX_NODES_PER_CALL) {
      console.log(`   ↳ ✂️ [${this.name}] Subsetting top ${MAX_NODES_PER_CALL} nodes to fit context limit.`);
      safeNodes = nodes.slice(0, MAX_NODES_PER_CALL);
    }
    const safeNodeIds = new Set(safeNodes.map((n) => n.id));
    const safeEdges = edges.filter((e) => safeNodeIds.has(e.source) || safeNodeIds.has(e.target));

    const userPrompt = buildReasonerUserMessage(this.name, safeNodes, safeEdges, graph.frameworks, graph.imports);

    try {
      const startTime = Date.now();
      const { completion, modelUsed } = await callGroqReasonerWithFallback([
        { role: 'system', content: STAGE_3_SYSTEM_PROMPT },
        { role: 'user', content: userPrompt }
      ], options);

      const elapsedTime = Date.now() - startTime;
      const rawContent = completion.choices[0]?.message?.content || '{}';

      let parsed;
      try {
        parsed = JSON.parse(rawContent);
      } catch (e) {
        console.error(`   ↳ ❌ [${this.name}] Failed to parse JSON output:`, e.message);
        return [];
      }

      const findings = Array.isArray(parsed.findings) ? parsed.findings : Array.isArray(parsed) ? parsed : [];
      console.log(`   ↳ 🎯 [${this.name}] Extracted ${findings.length} finding(s) using ${modelUsed} in ${elapsedTime}ms`);

      // Small pacing delay to respect TPM limits
      await new Promise((r) => setTimeout(r, 600));

      return findings.map((f) => ({
        ...f,
        reasoner: this.name
      }));
    } catch (err) {
      console.error(`   ↳ ❌ [${this.name}] All keys/models failed:`, err.message);
      return [];
    }
  }
}
