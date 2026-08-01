import { EvidenceGraphBuilder } from './evidenceGraphBuilder.js';
import { FindingMerger } from './findingMerger.js';
import {
  InjectionReasoner,
  AuthenticationReasoner,
  AuthorizationReasoner,
  FilesystemReasoner,
  CryptoReasoner,
  NetworkReasoner,
  DependencyReasoner,
  BusinessLogicReasoner
} from './reasoners/domainReasoners.js';
import { SecurityAdvisorService } from '../advisor/securityAdvisorService.js';

/**
 * SentinelAI Stage 3 - Repository Security Correlation Engine
 * Correlates structured evidence across the entire repository to produce security findings.
 */
export class SecurityCorrelationEngine {
  /**
   * Runs Stage 3 reasoning pipeline for an analysisId.
   * 
   * @param {Object} db - MongoDB database reference
   * @param {string} analysisId - Unique analysis ID
   * @param {Object} [options] - Options (model, etc.)
   * @returns {Promise<Object>} Correlation pipeline summary
   */
  static async processAnalysis(db, analysisId, options = {}) {
    if (!db) throw new Error('[SecurityCorrelationEngine] MongoDB reference required.');
    if (!analysisId) throw new Error('[SecurityCorrelationEngine] analysisId required.');

    const analysisCollection = db.collection('analysisResults');
    const findingsCollection = db.collection('security_findings');

    const analysis = await analysisCollection.findOne({ analysisId });
    if (!analysis) {
      throw new Error(`[SecurityCorrelationEngine] Analysis record not found for ID: ${analysisId}`);
    }

    const { repoFullName, repoId, userId } = analysis;

    console.log(`\n================================================================================`);
    console.log(`🛡️  [SENTINEL AI STAGE 3] Repository Security Correlation Engine`);
    console.log(`📌 Analysis ID:   ${analysisId}`);
    console.log(`📦 Repository:    ${repoFullName || 'Codebase'}`);
    console.log(`🤖 Model:         llama-3.3-70b-versatile (GROQ_LLAMA_PHASE_3)`);
    console.log(`================================================================================\n`);

    await analysisCollection.updateOne(
      { analysisId },
      { $set: { phase3Status: 'IN_PROGRESS', lastPhase3StartedAt: new Date() } }
    );

    // 1. Build in-memory repository evidence graph from MongoDB security_evidence collection
    console.log(`   ↳ 🔍 Loading evidence documents and building repository evidence graph...`);
    const graph = await EvidenceGraphBuilder.buildRepositoryGraph(db, analysisId);

    console.log(`   ↳ 📊 Repository Graph Built: ${graph.nodes.length} Nodes, ${graph.edges.length} Relationships, ${graph.frameworks.length} Frameworks.`);

    if (graph.nodes.length === 0) {
      console.warn(`⚠️ [SecurityCorrelationEngine] 0 evidence nodes found for analysisId ${analysisId}. Ensure Phase 2 ran successfully.`);
      await analysisCollection.updateOne(
        { analysisId },
        { $set: { phase3Status: 'SKIPPED_NO_EVIDENCE', totalFindingsCount: 0, updatedAt: new Date() } }
      );
      return { success: true, message: 'No evidence nodes found', totalFindings: 0 };
    }

    // 2. Instantiate all 8 Domain Reasoners
    const reasoners = [
      new InjectionReasoner(),
      new AuthenticationReasoner(),
      new AuthorizationReasoner(),
      new FilesystemReasoner(),
      new CryptoReasoner(),
      new NetworkReasoner(),
      new DependencyReasoner(),
      new BusinessLogicReasoner()
    ];

    const rawFindings = [];

    // 3. Execute domain reasoners sequentially
    console.log(`\n--------------------------------------------------------------------------------`);
    console.log(`⚡ Executing 8 Domain Security Reasoners...`);
    console.log(`--------------------------------------------------------------------------------`);

    for (const reasoner of reasoners) {
      try {
        const domainFindings = await reasoner.analyze(graph, options);
        rawFindings.push(...domainFindings);
      } catch (reasonerErr) {
        console.error(`   ↳ ❌ Error in ${reasoner.name}:`, reasonerErr.message);
      }
    }

    // 4. Merge & Deduplicate Findings across reasoners
    console.log(`\n--------------------------------------------------------------------------------`);
    console.log(`🔀 Merging and deduplicating ${rawFindings.length} raw findings across reasoners...`);
    const finalFindings = FindingMerger.mergeFindings(rawFindings, graph);

    // Calculate severity breakdown
    const findingsBySeverity = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };

    finalFindings.forEach((f) => {
      if (findingsBySeverity[f.severity] !== undefined) {
        findingsBySeverity[f.severity]++;
      }
    });

    console.log(`   ↳ 🎯 Final Deduplicated Findings: ${finalFindings.length}`);
    console.log(`   ↳ 🔴 Critical: ${findingsBySeverity.CRITICAL} | 🟠 High: ${findingsBySeverity.HIGH} | 🟡 Medium: ${findingsBySeverity.MEDIUM} | 🔵 Low: ${findingsBySeverity.LOW} | ⚪ Info: ${findingsBySeverity.INFO}`);

    // 5. Store findings in MongoDB security_findings collection
    if (finalFindings.length > 0) {
      const now = new Date();
      const operations = finalFindings.map((finding) => ({
        updateOne: {
          filter: { analysisId, finding_id: finding.finding_id },
          update: {
            $set: {
              ...finding,
              analysisId,
              repositoryId: repoId ? repoId.toString() : null,
              userId: userId ? userId.toString() : null,
              repoFullName,
              updatedAt: now
            },
            $setOnInsert: { createdAt: now }
          },
          upsert: true
        }
      }));

      await findingsCollection.bulkWrite(operations, { ordered: false });
      console.log(`   ↳ 💾 Saved ${finalFindings.length} finding document(s) to MongoDB collection [security_findings]`);
    }

    // 6. Update parent analysis document
    const finalStatus = 'COMPLETED';

    await analysisCollection.updateOne(
      { analysisId },
      {
        $set: {
          phase3Status: finalStatus,
          totalFindingsCount: finalFindings.length,
          findingsBySeverity,
          securityFindings: finalFindings,
          lastPhase3CompletedAt: new Date()
        }
      }
    );

    console.log(`================================================================================`);
    console.log(`🎉 [SENTINEL AI STAGE 3 COMPLETED] Status: ${finalStatus}`);
    console.log(`🛡️  Total Security Findings Identified: ${finalFindings.length}`);
    console.log(`================================================================================\n`);

    // AUTOMATICALLY TRIGGER PHASE 4 - Security Advisor & Report Generation Engine
    if (finalStatus !== 'FAILED') {
      console.log(`🚀 [PHASE 4 AUTO-TRIGGER] Handing off findings to SentinelAI Security Advisor & Report Generator...\n`);
      SecurityAdvisorService.processAnalysisReport(db, analysisId).catch((advErr) => {
        console.error(`❌ [Phase 4 Background Error] Report generation failed for ${analysisId}:`, advErr.message);
      });
    }

    return {
      success: true,
      status: finalStatus,
      analysisId,
      totalFindings: finalFindings.length,
      findingsBySeverity,
      findings: finalFindings
    };
  }
}
