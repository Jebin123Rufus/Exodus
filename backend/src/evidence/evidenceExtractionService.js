import Groq from 'groq-sdk';
import { PHASE_2_SYSTEM_PROMPT, buildUserMessage } from './evidencePrompts.js';
import { SecurityCorrelationEngine } from '../correlation/correlationEngine.js';

// Available API Keys Pool
function getApiKeyPool() {
  const keys = [
    process.env.GROQ_LLAMA_PHASE_2,
    process.env.GROQ_API_KEY,
    process.env.GROQ_LLAMA_PHASE_3
  ].filter((k) => typeof k === 'string' && k.trim().length > 10);

  // Return unique keys
  return [...new Set(keys)];
}

// Model Fallback Hierarchy
const MODEL_FALLBACK_LIST = [
  'llama-3.3-70b-versatile',
  'llama-3.1-8b-instant',
  'llama3-8b-8192',
  'mixtral-8x7b-32768'
];

/**
 * Executes a Groq LLM completion with automatic API key rotation and model fallback.
 */
async function callGroqWithFallback(messages, options = {}) {
  const apiKeys = getApiKeyPool();
  if (apiKeys.length === 0) {
    throw new Error('[EvidenceExtractionService] No Groq API keys found in environment variables!');
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
          max_completion_tokens: options.max_completion_tokens || 4096,
          response_format: { type: 'json_object' }
        });

        return { completion, modelUsed: modelCandidate };
      } catch (err) {
        lastError = err;
        const isRateLimit = err.status === 429 || (err.message && err.message.includes('rate_limit_exceeded'));
        if (isRateLimit) {
          console.warn(`   ↳ ⚠️ Rate limit (429) on ${modelCandidate} with key ...${apiKey.slice(-6)}. Trying next key/model...`);
          // Brief pause before trying next key/model
          await new Promise((r) => setTimeout(r, 400));
          continue;
        } else {
          // For non-rate-limit errors, break to next model
          break;
        }
      }
    }
  }

  throw lastError || new Error('All Groq API keys and models exhausted due to rate limits.');
}

/**
 * SentinelAI Phase 2 - Universal Security Evidence Extraction Service
 */
export class EvidenceExtractionService {
  /**
   * Processes all semantic chunks for an analysis using Groq LLaMA models
   * to build a unified Security Evidence Graph.
   * 
   * @param {Object} db - MongoDB database reference
   * @param {string} analysisId - Unique analysis ID
   * @param {Object} [options] - Optional settings
   * @returns {Promise<Object>} Aggregated Evidence Graph summary
   */
  static async processAnalysisEvidence(db, analysisId, options = {}) {
    if (!db) throw new Error('[EvidenceExtractionService] MongoDB reference required.');
    if (!analysisId) throw new Error('[EvidenceExtractionService] analysisId required.');

    // 1. Fetch parent analysis document
    const analysisCollection = db.collection('analysisResults');
    const chunksCollection = db.collection('semantic_chunks');
    const evidenceCollection = db.collection('security_evidence');

    const analysis = await analysisCollection.findOne({ analysisId });
    if (!analysis) {
      throw new Error(`[EvidenceExtractionService] Analysis record not found for ID: ${analysisId}`);
    }

    const { repoFullName, repoId, userId } = analysis;

    // 2. Fetch all semantic chunks for this analysis
    const chunks = await chunksCollection
      .find({ analysisId })
      .sort({ filePath: 1, chunkIndex: 1 })
      .toArray();

    const totalChunks = chunks.length;

    console.log(`\n================================================================================`);
    console.log(`🧠 [SENTINEL AI PHASE 2] Universal Security Evidence Extraction Engine`);
    console.log(`📌 Analysis ID:   ${analysisId}`);
    console.log(`📦 Repository:    ${repoFullName || 'Codebase'}`);
    console.log(`📄 Total Chunks:  ${totalChunks}`);
    console.log(`🤖 Model:         llama-3.3-70b-versatile (With Multi-Key & Model Fallback)`);
    console.log(`================================================================================\n`);

    if (totalChunks === 0) {
      console.warn(`⚠️ [EvidenceExtractionService] No semantic chunks found for ${analysisId}. Ensure Phase 1.5 chunking ran successfully.`);
      await analysisCollection.updateOne(
        { analysisId },
        { $set: { phase2Status: 'SKIPPED_NO_CHUNKS', updatedAt: new Date() } }
      );
      return { success: true, message: 'No chunks to process', totalNodes: 0, totalEdges: 0 };
    }

    await analysisCollection.updateOne(
      { analysisId },
      { $set: { phase2Status: 'IN_PROGRESS', lastPhase2StartedAt: new Date() } }
    );

    const allExtractedNodes = [];
    const allExtractedEdges = [];
    const aggregatedFrameworks = new Set();
    const aggregatedImports = new Set();

    let processedCount = 0;
    let successCount = 0;
    let failedCount = 0;

    // 3. Process each semantic chunk sequentially
    for (const chunk of chunks) {
      const chunkDesc = `${chunk.filePath} (Chunk ${chunk.chunkIndex + 1}/${chunk.totalChunks}, L${chunk.startLine}-L${chunk.endLine})`;
      console.log(`--------------------------------------------------------------------------------`);
      console.log(`📄 [Chunk ${processedCount + 1}/${totalChunks}]: ${chunkDesc}`);

      try {
        // --- TOKEN GUARD: truncate content to stay safely under Groq TPM limits ---
        const MAX_CONTENT_CHARS = 18000;
        let safeChunk = chunk;
        if (chunk.content && chunk.content.length > MAX_CONTENT_CHARS) {
          const truncated = chunk.content.substring(0, MAX_CONTENT_CHARS);
          const cutLine = (truncated.match(/\n/g) || []).length + 1;
          console.log(`   ↳ ✂️ Content truncated to ${MAX_CONTENT_CHARS} chars (${chunk.content.length} total) to stay within TPM limit`);
          safeChunk = { ...chunk, content: truncated + '\n/* [TRUNCATED FOR TOKEN LIMIT] */', endLine: cutLine };
        }

        const userPrompt = buildUserMessage(safeChunk);
        const startTime = Date.now();

        console.log(`   ↳ 🤖 Sending request to Groq API...`);

        const { completion, modelUsed } = await callGroqWithFallback([
          { role: 'system', content: PHASE_2_SYSTEM_PROMPT },
          { role: 'user', content: userPrompt }
        ], options);

        const elapsedTime = Date.now() - startTime;
        const rawContent = completion.choices[0]?.message?.content || '{}';

        let parsedData;
        try {
          parsedData = JSON.parse(rawContent);
        } catch (jsonErr) {
          console.error(`   ↳ ❌ Failed to parse Groq JSON response for ${chunk.chunkId}:`, jsonErr.message);
          parsedData = { language: chunk.language, frameworks: [], imports: [], nodes: [], edges: [] };
        }

        const nodes = Array.isArray(parsedData.nodes) ? parsedData.nodes : [];
        const edges = Array.isArray(parsedData.edges) ? parsedData.edges : [];
        const frameworks = Array.isArray(parsedData.frameworks) ? parsedData.frameworks : [];
        const imports = Array.isArray(parsedData.imports) ? parsedData.imports : [];

        // Normalize node IDs and associate chunk metadata
        const normalizedNodes = nodes.map((node, nIdx) => {
          const rawId = node.id || `node_${nIdx}`;
          const globalId = `${chunk.filePath}:${chunk.chunkIndex}:${rawId}`;
          return {
            ...node,
            id: globalId,
            rawId,
            chunkId: chunk.chunkId,
            file: chunk.filePath,
            start_line: node.start_line || chunk.startLine,
            end_line: node.end_line || chunk.endLine,
            confidence: typeof node.confidence === 'number' ? node.confidence : 1.0
          };
        });

        // Normalize edge sources and targets to global IDs
        const normalizedEdges = edges.map((edge) => {
          const srcGlobal = `${chunk.filePath}:${chunk.chunkIndex}:${edge.source}`;
          const tgtGlobal = `${chunk.filePath}:${chunk.chunkIndex}:${edge.target}`;
          return {
            ...edge,
            source: srcGlobal,
            target: tgtGlobal,
            rawSource: edge.source,
            rawTarget: edge.target,
            chunkId: chunk.chunkId,
            file: chunk.filePath,
            confidence: typeof edge.confidence === 'number' ? edge.confidence : 1.0
          };
        });

        frameworks.forEach((f) => aggregatedFrameworks.add(f));
        imports.forEach((imp) => aggregatedImports.add(imp));

        allExtractedNodes.push(...normalizedNodes);
        allExtractedEdges.push(...normalizedEdges);

        // Store chunk evidence document in MongoDB
        const evidenceDoc = {
          analysisId,
          repositoryId: repoId ? repoId.toString() : null,
          userId: userId ? userId.toString() : null,
          filePath: chunk.filePath,
          chunkId: chunk.chunkId,
          chunkIndex: chunk.chunkIndex,
          language: parsedData.language || chunk.language,
          frameworks,
          imports,
          nodesCount: normalizedNodes.length,
          edgesCount: normalizedEdges.length,
          nodes: normalizedNodes,
          edges: normalizedEdges,
          rawLlmResponse: parsedData,
          updatedAt: new Date()
        };

        await evidenceCollection.updateOne(
          { analysisId, chunkId: chunk.chunkId },
          { $set: evidenceDoc, $setOnInsert: { createdAt: new Date() } },
          { upsert: true }
        );

        // Update chunk status in semantic_chunks
        await chunksCollection.updateOne(
          { analysisId, chunkId: chunk.chunkId },
          { $set: { status: 'COMPLETED', evidenceExtracted: true, evidenceNodesCount: normalizedNodes.length, updatedAt: new Date() } }
        );

        successCount++;
        console.log(`   ↳ 🎯 Extracted ${normalizedNodes.length} Security Nodes & ${normalizedEdges.length} Relationships in ${elapsedTime}ms (Model: ${modelUsed})`);
        if (frameworks.length > 0) {
          console.log(`   ↳ 🧩 Frameworks Detected: ${frameworks.join(', ')}`);
        }

        // Pacing delay between chunks to prevent TPM spikes
        await new Promise((r) => setTimeout(r, 600));

      } catch (chunkErr) {
        console.error(`   ↳ ❌ Error extracting evidence for chunk ${chunk.chunkId}:`, chunkErr.message);
        failedCount++;
        await chunksCollection.updateOne(
          { analysisId, chunkId: chunk.chunkId },
          { $set: { status: 'FAILED', extractionError: chunkErr.message, updatedAt: new Date() } }
        );
      }

      processedCount++;
    }

    // 4. Build unified aggregated Security Evidence Graph
    const aggregatedGraph = {
      analysisId,
      repoFullName,
      frameworks: Array.from(aggregatedFrameworks),
      imports: Array.from(aggregatedImports),
      totalNodes: allExtractedNodes.length,
      totalEdges: allExtractedEdges.length,
      nodes: allExtractedNodes,
      edges: allExtractedEdges,
      updatedAt: new Date()
    };

    const finalPhase2Status = failedCount === 0 ? 'COMPLETED' : successCount > 0 ? 'PARTIAL_SUCCESS' : 'FAILED';

    await analysisCollection.updateOne(
      { analysisId },
      {
        $set: {
          phase2Status: finalPhase2Status,
          extractedEvidenceCount: allExtractedNodes.length,
          extractedEdgesCount: allExtractedEdges.length,
          evidenceGraph: aggregatedGraph,
          lastPhase2CompletedAt: new Date()
        }
      }
    );

    console.log(`================================================================================`);
    console.log(`🎉 [SENTINEL AI PHASE 2 COMPLETED] Status: ${finalPhase2Status}`);
    console.log(`📊 Total Security Nodes Extracted:        ${allExtractedNodes.length}`);
    console.log(`🔗 Total Relationships Extracted:         ${allExtractedEdges.length}`);
    console.log(`🧩 Frameworks Identified:                 ${Array.from(aggregatedFrameworks).join(', ') || 'None'}`);
    console.log(`💾 Saved to MongoDB [security_evidence] and updated analysis record.`);
    console.log(`================================================================================\n`);

    // AUTOMATICALLY TRIGGER STAGE 3 - Repository Security Correlation Engine
    if (finalPhase2Status !== 'FAILED' && allExtractedNodes.length > 0) {
      console.log(`🚀 [STAGE 3 AUTO-TRIGGER] Handing off ${allExtractedNodes.length} nodes & ${allExtractedEdges.length} edges to SentinelAI Correlation Engine...\n`);
      SecurityCorrelationEngine.processAnalysis(db, analysisId).catch((corrErr) => {
        console.error(`❌ [Stage 3 Background Error] Security correlation failed for ${analysisId}:`, corrErr.message);
      });
    }

    return {
      success: finalPhase2Status !== 'FAILED',
      status: finalPhase2Status,
      analysisId,
      totalChunks,
      processedChunks: processedCount,
      totalNodes: allExtractedNodes.length,
      totalEdges: allExtractedEdges.length,
      frameworks: Array.from(aggregatedFrameworks)
    };
  }
}
