import Groq from 'groq-sdk';
import { PHASE_4_SYSTEM_PROMPT, buildAdvisorUserMessage } from './advisorPrompts.js';

// API Key Pool for Phase 4
function getApiKeyPool() {
  const keys = [
    process.env.GROQ_LLAMA_PHASE_4,
    process.env.GROQ_LLAMA_PHASE_3,
    process.env.GROQ_LLAMA_PHASE_2,
    process.env.GROQ_API_KEY
  ].filter((k) => typeof k === 'string' && k.trim().length > 10);
  return [...new Set(keys)];
}

const MODEL_FALLBACK_LIST = [
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'llama3-8b-8192',
  'mixtral-8x7b-32768'
];

/**
 * Executes a Groq LLM completion with key rotation & model fallback for Phase 4.
 */
async function callGroqAdvisorWithFallback(messages, options = {}) {
  const apiKeys = getApiKeyPool();
  if (apiKeys.length === 0) {
    throw new Error('[SecurityAdvisorService] No Groq API keys found in environment variables!');
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
          temperature: 0.1,
          max_completion_tokens: 3072,
          response_format: { type: 'json_object' }
        });

        return { completion, modelUsed: modelCandidate };
      } catch (err) {
        lastError = err;
        const isRateLimit = err.status === 429 || (err.message && err.message.includes('rate_limit_exceeded'));
        if (isRateLimit) {
          console.warn(`   ↳ ⚠️ Rate limit (429) on ${modelCandidate} in Phase 4. Trying next key/model...`);
          await new Promise((r) => setTimeout(r, 400));
          continue;
        } else {
          break;
        }
      }
    }
  }

  throw lastError || new Error('All Groq API keys and models exhausted in Phase 4.');
}

/**
 * SentinelAI Phase 4 – Security Advisor & Enterprise Report Generation Service
 */
export class SecurityAdvisorService {
  /**
   * Generates enterprise security report from Phase 3 findings.
   * 
   * @param {Object} db - MongoDB database reference
   * @param {string} analysisId - Unique analysis ID
   * @param {Object} [options] - Options
   * @returns {Promise<Object>} Generated report summary
   */
  static async processAnalysisReport(db, analysisId, options = {}) {
    if (!db) throw new Error('[SecurityAdvisorService] MongoDB reference required.');
    if (!analysisId) throw new Error('[SecurityAdvisorService] analysisId required.');

    const analysisCollection = db.collection('analysisResults');
    const chunksCollection = db.collection('semantic_chunks');
    const evidenceCollection = db.collection('security_evidence');
    const findingsCollection = db.collection('security_findings');
    const reportsCollection = db.collection('security_reports');

    const analysis = await analysisCollection.findOne({ analysisId });
    if (!analysis) {
      throw new Error(`[SecurityAdvisorService] Analysis record not found for ID: ${analysisId}`);
    }

    const { repoFullName, repoId, userId } = analysis;

    console.log(`\n================================================================================`);
    console.log(`📋 [SENTINEL AI PHASE 4] Security Advisor & Enterprise Report Generator`);
    console.log(`📌 Analysis ID:   ${analysisId}`);
    console.log(`📦 Repository:    ${repoFullName || 'Codebase'}`);
    console.log(`🤖 Model:         llama-3.3-70b-versatile (GROQ_LLAMA_PHASE_4)`);
    console.log(`================================================================================\n`);

    await analysisCollection.updateOne(
      { analysisId },
      { $set: { phase4Status: 'IN_PROGRESS', lastPhase4StartedAt: new Date() } }
    );

    // 1. Load statistics & findings
    const totalFilesScanned = analysis.completedFiles || 0;
    const totalChunks = await chunksCollection.countDocuments({ analysisId });
    const evidenceDocs = await evidenceCollection.find({ analysisId }).toArray();
    let totalArtifacts = 0;
    let totalRelationships = 0;
    for (const doc of evidenceDocs) {
      totalArtifacts += doc.nodesCount || (doc.nodes ? doc.nodes.length : 0);
      totalRelationships += doc.edgesCount || (doc.edges ? doc.edges.length : 0);
    }

    const rawFindings = await findingsCollection.find({ analysisId }).toArray();
    const totalFindings = rawFindings.length;

    // Calculate Severity Breakdown & Security Score
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    rawFindings.forEach((f) => {
      const sev = (f.severity || 'MEDIUM').toUpperCase();
      if (severityCounts[sev] !== undefined) severityCounts[sev]++;
    });

    const overallSecurityScore = calculateOverallSecurityScore(severityCounts);

    console.log(`   ↳ 📊 Scan Stats: ${totalFilesScanned} Files, ${totalChunks} Chunks, ${totalArtifacts} Artifacts, ${totalRelationships} Relationships.`);
    console.log(`   ↳ 🎯 Findings: ${totalFindings} total (Critical: ${severityCounts.CRITICAL}, High: ${severityCounts.HIGH}, Medium: ${severityCounts.MEDIUM}, Low: ${severityCounts.LOW}, Info: ${severityCounts.INFO}).`);
    console.log(`   ↳ 🛡️  Calculated Overall Security Score: ${overallSecurityScore}/100`);

    // 2. Enrich findings using Phase 4 LLM
    const enrichedFindings = [];
    let enrichedCount = 0;

    for (const finding of rawFindings) {
      console.log(`   ↳ 🧠 Enriching finding ${enrichedCount + 1}/${totalFindings}: "${finding.title}"...`);

      // Find matching node evidence
      const nodeIds = new Set(finding.evidence_node_ids || []);
      const matchedNodes = [];
      for (const doc of evidenceDocs) {
        if (Array.isArray(doc.nodes)) {
          doc.nodes.forEach((n) => {
            if (nodeIds.has(n.id)) matchedNodes.push(n);
          });
        }
      }

      try {
        const userPrompt = buildAdvisorUserMessage(finding, matchedNodes);
        const { completion, modelUsed } = await callGroqAdvisorWithFallback([
          { role: 'system', content: PHASE_4_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt }
        ], options);

        const rawContent = completion.choices[0]?.message?.content || '{}';
        let enrichedData;
        try {
          enrichedData = JSON.parse(rawContent);
        } catch (e) {
          enrichedData = {};
        }

        // Fallback fields if LLM omits any required keys
        const enrichedItem = {
          finding_id: finding.finding_id,
          category: finding.category,
          title: finding.title,
          severity: finding.severity,
          confidence: finding.confidence,
          affected_files: finding.affected_files,
          evidence_node_ids: finding.evidence_node_ids,
          evidence_edge_ids: finding.evidence_edge_ids,
          executive_summary: enrichedData.executive_summary || finding.description || 'Information Not Available',
          technical_description: enrichedData.technical_description || finding.reasoning || 'Information Not Available',
          business_impact: enrichedData.business_impact || 'Potential unauthorized access or compromise.',
          technical_impact: Array.isArray(enrichedData.technical_impact) ? enrichedData.technical_impact : ['Confidentiality', 'Integrity'],
          root_cause_analysis: enrichedData.root_cause_analysis || 'Insecure coding pattern or missing validation check.',
          exact_location: {
            file_path: finding.affected_files?.[0] || 'unknown',
            function: enrichedData.exact_location?.function || 'N/A',
            start_line: enrichedData.exact_location?.start_line || 1,
            end_line: enrichedData.exact_location?.end_line || 1,
            code_snippet: matchedNodes[0]?.code || 'Information Not Available'
          },
          evidence_chain: Array.isArray(enrichedData.evidence_chain) && enrichedData.evidence_chain.length > 0 ? enrichedData.evidence_chain : (finding.attack_path || ['Evidence Node -> Finding']),
          exploitation_scenario: enrichedData.exploitation_scenario || 'An attacker could exploit this condition under unauthorized parameters.',
          secure_code_fix: enrichedData.secure_code_fix || '// Use parameterized queries / input validation',
          fix_explanation: enrichedData.fix_explanation || 'Replaced direct concatenation with safe APIs.',
          secure_coding_guidance: enrichedData.secure_coding_guidance || 'Follow framework security guidelines and validate inputs.',
          long_term_prevention: Array.isArray(enrichedData.long_term_prevention) ? enrichedData.long_term_prevention : ['Implement automated security static analysis in CI/CD.'],
          standards_mapping: enrichedData.standards_mapping || { cwe: 'CWE-20', owasp_top_10: 'A03:2021-Injection' },
          risk_assessment: enrichedData.risk_assessment || {
            severity: finding.severity,
            confidence: finding.confidence,
            priority_score: finding.severity === 'CRITICAL' ? 10 : finding.severity === 'HIGH' ? 8 : 5,
            business_risk: finding.severity,
            technical_risk: finding.severity,
            remediation_difficulty: 'MEDIUM',
            exploitability: 'MEDIUM',
            reachability: 'DIRECT'
          },
          remediation_checklist: Array.isArray(enrichedData.remediation_checklist) ? enrichedData.remediation_checklist : ['Validate input parameters', 'Add unit tests'],
          references: Array.isArray(enrichedData.references) ? enrichedData.references : ['https://owasp.org'],
          modelUsed
        };

        enrichedFindings.push(enrichedItem);
        enrichedCount++;
        await new Promise((r) => setTimeout(r, 400));
      } catch (err) {
        console.error(`   ↳ ❌ Error enriching finding ${finding.finding_id}:`, err.message);
        // Fallback item without breaking
        enrichedFindings.push({
          finding_id: finding.finding_id,
          category: finding.category,
          title: finding.title,
          severity: finding.severity,
          confidence: finding.confidence,
          affected_files: finding.affected_files,
          evidence_node_ids: finding.evidence_node_ids,
          executive_summary: finding.description,
          technical_description: finding.reasoning,
          business_impact: 'Information Not Available',
          technical_impact: ['Confidentiality', 'Integrity'],
          root_cause_analysis: 'Information Not Available',
          exact_location: { file_path: finding.affected_files?.[0] || 'N/A', start_line: 1, end_line: 1, code_snippet: 'Information Not Available' },
          evidence_chain: finding.attack_path || [],
          exploitation_scenario: 'Information Not Available',
          secure_code_fix: '// Information Not Available',
          fix_explanation: 'Information Not Available',
          secure_coding_guidance: 'Follow OWASP guidelines',
          long_term_prevention: ['Enable security scanning'],
          standards_mapping: {},
          risk_assessment: { severity: finding.severity, confidence: finding.confidence, priority_score: 5 },
          remediation_checklist: ['Review code'],
          references: ['https://owasp.org']
        });
      }
    }

    // 3. Construct Complete Structured Enterprise Report JSON
    const reportJson = {
      analysis: {
        analysisId,
        repoFullName,
        repoId: repoId ? repoId.toString() : null,
        userId: userId ? userId.toString() : null
      },
      summary: {
        overallSecurityScore,
        grade: getScoreGrade(overallSecurityScore),
        total: totalFindings,
        critical: severityCounts.CRITICAL,
        high: severityCounts.HIGH,
        medium: severityCounts.MEDIUM,
        low: severityCounts.LOW,
        info: severityCounts.INFO
      },
      statistics: {
        filesScanned: totalFilesScanned,
        chunksProcessed: totalChunks,
        artifactsExtracted: totalArtifacts,
        relationshipsBuilt: totalRelationships,
        findingsGenerated: totalFindings
      },
      executive_summary: {
        title: `SentinelAI Application Security Assessment for ${repoFullName || 'Repository'}`,
        overview: `Static security analysis evaluated ${totalFilesScanned} source files and ${totalArtifacts} security evidence nodes. Identified ${totalFindings} validated security findings resulting in an Overall Security Score of ${overallSecurityScore}/100.`,
        key_risks: enrichedFindings.filter((f) => ['CRITICAL', 'HIGH'].includes(f.severity)).map((f) => f.title)
      },
      findings: enrichedFindings,
      developer_report: {
        remediation_priorities: enrichedFindings
          .sort((a, b) => (b.risk_assessment?.priority_score || 0) - (a.risk_assessment?.priority_score || 0))
          .map((f) => ({ finding_id: f.finding_id, title: f.title, priority: f.risk_assessment?.priority_score || 5, file: f.affected_files?.[0] }))
      },
      references: [
        'https://owasp.org/www-project-top-ten/',
        'https://cwe.mitre.org/',
        'https://attack.mitre.org/'
      ],
      generated_at: new Date().toISOString()
    };

    // 4. Construct Markdown Report representation
    const reportMarkdown = generateMarkdownReport(reportJson);

    // 5. Store report in MongoDB security_reports collection
    const reportDoc = {
      analysisId,
      repositoryId: repoId ? repoId.toString() : null,
      userId: userId ? userId.toString() : null,
      repoFullName,
      overallSecurityScore,
      summary: reportJson.summary,
      statistics: reportJson.statistics,
      reportJson,
      reportMarkdown,
      updatedAt: new Date()
      // NOTE: createdAt is set only via $setOnInsert to avoid MongoDB conflict
    };

    await reportsCollection.updateOne(
      { analysisId },
      { $set: reportDoc, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );

    // 6. Update parent analysis record
    const finalPhase4Status = 'COMPLETED';

    await analysisCollection.updateOne(
      { analysisId },
      {
        $set: {
          phase4Status: finalPhase4Status,
          overallSecurityScore,
          reportId: analysisId,
          lastPhase4CompletedAt: new Date()
        }
      }
    );

    console.log(`================================================================================`);
    console.log(`🎉 [SENTINEL AI PHASE 4 COMPLETED] Status: ${finalPhase4Status}`);
    console.log(`🛡️  Overall Security Score:               ${overallSecurityScore}/100 (${getScoreGrade(overallSecurityScore)})`);
    console.log(`📋 Total Enriched Report Findings:        ${enrichedFindings.length}`);
    console.log(`💾 Report saved to MongoDB collection [security_reports]`);
    console.log(`================================================================================\n`);

    return {
      success: true,
      status: finalPhase4Status,
      analysisId,
      overallSecurityScore,
      grade: getScoreGrade(overallSecurityScore),
      totalFindings: enrichedFindings.length,
      reportJson
    };
  }
}

/**
 * Calculates Overall Security Score (0 to 100) based on findings.
 */
function calculateOverallSecurityScore(severityCounts) {
  let score = 100;
  score -= (severityCounts.CRITICAL || 0) * 25;
  score -= (severityCounts.HIGH || 0) * 15;
  score -= (severityCounts.MEDIUM || 0) * 8;
  score -= (severityCounts.LOW || 0) * 3;
  return Math.max(0, Math.min(100, score));
}

/**
 * Returns security grade letter.
 */
function getScoreGrade(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Formats Markdown string for report export.
 */
function generateMarkdownReport(reportJson) {
  const { analysis, summary, statistics, executive_summary, findings } = reportJson;

  let md = `# SentinelAI Security Report: ${analysis.repoFullName || 'Repository'}\n\n`;
  md += `**Generated At**: ${reportJson.generated_at}\n`;
  md += `**Analysis ID**: \`${analysis.analysisId}\`  \n`;
  md += `**Overall Security Score**: **${summary.overallSecurityScore}/100** (Grade: ${summary.grade})\n\n`;

  md += `## 📊 Executive Summary\n\n${executive_summary.overview}\n\n`;

  md += `### Scan Statistics\n`;
  md += `- **Files Scanned**: ${statistics.filesScanned}\n`;
  md += `- **Chunks Processed**: ${statistics.chunksProcessed}\n`;
  md += `- **Artifacts Extracted**: ${statistics.artifactsExtracted}\n`;
  md += `- **Relationships Built**: ${statistics.relationshipsBuilt}\n`;
  md += `- **Total Findings**: ${statistics.findingsGenerated}\n\n`;

  md += `### Findings Breakdown\n`;
  md += `- 🔴 **Critical**: ${summary.critical}\n`;
  md += `- 🟠 **High**: ${summary.high}\n`;
  md += `- 🟡 **Medium**: ${summary.medium}\n`;
  md += `- 🔵 **Low**: ${summary.low}\n`;
  md += `- ⚪ **Info**: ${summary.info}\n\n`;

  md += `\n---\n\n## 🛡️ Detailed Findings\n\n`;

  findings.forEach((f, idx) => {
    md += `### ${idx + 1}. [${f.severity}] ${f.title}\n\n`;
    md += `- **Category**: ${f.category}\n`;
    md += `- **Confidence**: ${(f.confidence * 100).toFixed(0)}%\n`;
    md += `- **Affected File**: \`${f.affected_files?.[0] || 'N/A'}\` (L${f.exact_location?.start_line || 1}-L${f.exact_location?.end_line || 1})\n\n`;

    md += `#### Executive Summary\n${f.executive_summary}\n\n`;
    md += `#### Technical Description & Root Cause\n${f.technical_description}\n\n`;
    md += `#### Business Impact\n${f.business_impact}\n\n`;

    if (f.evidence_chain && f.evidence_chain.length > 0) {
      md += `#### Evidence Chain\n\`\`\`\n${f.evidence_chain.join(' → ')}\n\`\`\`\n\n`;
    }

    if (f.exact_location?.code_snippet) {
      md += `#### Vulnerable Code\n\`\`\`\n${f.exact_location.code_snippet}\n\`\`\`\n\n`;
    }

    if (f.secure_code_fix) {
      md += `#### Recommended Secure Code Fix\n\`\`\`\n${f.secure_code_fix}\n\`\`\`\n`;
      md += `*Fix Explanation*: ${f.fix_explanation}\n\n`;
    }

    md += `---\n\n`;
  });

  return md;
}
