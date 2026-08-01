import crypto from 'crypto';

/**
 * Finding Merger & Anti-False-Positive Filter
 * Deduplicates raw findings from all reasoners and filters out low-confidence speculative findings.
 */
export class FindingMerger {
  /**
   * Deduplicates and normalizes raw findings from all reasoners.
   * 
   * @param {Array<Object>} rawFindings - List of finding objects from reasoners
   * @param {EvidenceGraph} graph - Repository Evidence Graph
   * @returns {Array<Object>} Final deduplicated & validated findings
   */
  static mergeFindings(rawFindings, graph) {
    if (!Array.isArray(rawFindings) || rawFindings.length === 0) {
      return [];
    }

    const findingMap = new Map();

    for (const raw of rawFindings) {
      if (!raw || !raw.title || typeof raw.title !== 'string') continue;

      const title = raw.title.trim();
      if (title.length < 5) continue;

      const category = raw.category || 'Security Misconfiguration';
      const affectedFiles = Array.isArray(raw.affected_files) ? raw.affected_files : [];
      const primaryFile = affectedFiles[0] || 'repository';

      const computedConfidence = calculateCalculatedConfidence(raw, graph);

      // FALSE POSITIVE FILTER 1: Skip low-confidence speculative findings (< 0.70)
      if (computedConfidence < 0.70) {
        console.log(`   ↳ 🛡️ [False Positive Filter] Discarded low-confidence finding (${computedConfidence}): "${title}"`);
        continue;
      }

      // FALSE POSITIVE FILTER 2: Discard findings flagged as needs_more_evidence unless heavily corroborated
      if (raw.needs_more_evidence && computedConfidence < 0.85) {
        console.log(`   ↳ 🛡️ [False Positive Filter] Discarded incomplete finding needing more evidence: "${title}"`);
        continue;
      }

      // Hash key for deduplication
      const dedupeKey = `${category.toLowerCase()}:${title.toLowerCase()}:${primaryFile}`;

      if (!findingMap.has(dedupeKey)) {
        const findingId = generateDeterministicFindingId(category, title, primaryFile);

        findingMap.set(dedupeKey, {
          finding_id: findingId,
          category,
          title,
          description: raw.description || '',
          severity: normalizeSeverity(raw.severity),
          confidence: computedConfidence,
          affected_files: [...new Set(affectedFiles)],
          evidence_node_ids: [...new Set(Array.isArray(raw.evidence_node_ids) ? raw.evidence_node_ids : [])],
          evidence_edge_ids: [...new Set(Array.isArray(raw.evidence_edge_ids) ? raw.evidence_edge_ids : [])],
          reasoning: raw.reasoning || '',
          attack_path: Array.isArray(raw.attack_path) ? raw.attack_path : [],
          recommended_fix: raw.recommended_fix || '',
          needs_more_evidence: Boolean(raw.needs_more_evidence),
          reasoner: raw.reasoner || 'UnknownReasoner'
        });
      } else {
        // Merge into existing finding
        const existing = findingMap.get(dedupeKey);
        existing.affected_files = [...new Set([...existing.affected_files, ...affectedFiles])];
        existing.evidence_node_ids = [...new Set([...existing.evidence_node_ids, ...(raw.evidence_node_ids || [])])];
        existing.evidence_edge_ids = [...new Set([...existing.evidence_edge_ids, ...(raw.evidence_edge_ids || [])])];
        if (computedConfidence > existing.confidence) {
          existing.confidence = computedConfidence;
        }
        if (raw.description && raw.description.length > existing.description.length) {
          existing.description = raw.description;
        }
        if (raw.recommended_fix && !existing.recommended_fix) {
          existing.recommended_fix = raw.recommended_fix;
        }
      }
    }

    return Array.from(findingMap.values());
  }
}

/**
 * Generates a deterministic finding ID.
 */
function generateDeterministicFindingId(category, title, primaryFile) {
  const hash = crypto
    .createHash('sha256')
    .update(`${category}:${title}:${primaryFile}`)
    .digest('hex')
    .substring(0, 24);
  return `fnd_${hash}`;
}

/**
 * Normalizes severity string to valid enum.
 */
function normalizeSeverity(sev) {
  if (!sev) return 'MEDIUM';
  const upper = String(sev).toUpperCase();
  if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(upper)) {
    return upper;
  }
  return 'MEDIUM';
}

/**
 * Calculates final confidence based on evidence completeness and node corroboration.
 */
function calculateCalculatedConfidence(finding, graph) {
  const llmConf = typeof finding.confidence === 'number' ? finding.confidence : 0.70;
  const nodeIds = Array.isArray(finding.evidence_node_ids) ? finding.evidence_node_ids : [];

  let validNodes = 0;
  for (const id of nodeIds) {
    if (graph && graph.nodeIndex && graph.nodeIndex.has(id)) validNodes++;
  }

  // Corroboration bonus if multiple evidence nodes support the finding
  const corroborationBonus = validNodes > 1 ? 0.10 : 0.0;
  const finalConf = Math.min(1.0, Math.max(0.10, llmConf + corroborationBonus));

  return parseFloat(finalConf.toFixed(2));
}
