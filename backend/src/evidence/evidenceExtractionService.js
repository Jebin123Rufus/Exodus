import Groq from 'groq-sdk';
import { PHASE_2_SYSTEM_PROMPT, buildUserMessage } from './evidencePrompts.js';

let groqPhase2Client = null;

/**
 * Initializes and retrieves the Groq SDK client using the GROQ_LLAMA_PHASE_2 key.
 * @returns {Groq} Groq SDK instance
 */
function getGroqClient() {
  if (!groqPhase2Client) {
    const apiKey = process.env.GROQ_LLAMA_PHASE_2 || process.env.GROQ_API_KEY;
    if (!apiKey) {
      throw new Error('[EvidenceExtractionService] GROQ_LLAMA_PHASE_2 API key is missing in environment variables!');
    }
    groqPhase2Client = new Groq({ apiKey });
  }
  return groqPhase2Client;
}

/**
 * SentinelAI Phase 2 - Universal Security Evidence Extraction Service
 */
export class EvidenceExtractionService {
  /**
   * Processes all semantic chunks for an analysis using Groq LLaMA 3.3 70B
   * to build a unified Security Evidence Graph.
   * 
   * @param {Object} db - MongoDB database reference
   * @param {string} analysisId - Unique analysis ID
   * @param {Object} [options] - Optional settings (model, temperature, maxConcurrency)
   * @returns {Promise<Object>} Aggregated Evidence Graph summary
   */
  static async processAnalysisEvidence(db, analysisId, options = {}) {
    if (!db) throw new Error('[EvidenceExtractionService] MongoDB reference required.');
    if (!analysisId) throw new Error('[EvidenceExtractionService] analysisId required.');

    const groq = getGroqClient();

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
    console.log(`🤖 Model:         llama-3.3-70b-versatile (GROQ_LLAMA_PHASE_2)`);
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

    const modelName = options.model || 'llama-3.3-70b-versatile';
    const allExtractedNodes = [];
    const allExtractedEdges = [];
    const aggregatedFrameworks = new Set();
    const aggregatedImports = new Set();

    let processedCount = 0;
    let successCount = 0;
    let failedCount = 0;

    // 3. Process each semantic chunk sequentially / safely
    for (const chunk of chunks) {
      const chunkDesc = `${chunk.filePath} (Chunk ${chunk.chunkIndex + 1}/${chunk.totalChunks}, L${chunk.startLine}-L${chunk.endLine})`;
      console.log(`--------------------------------------------------------------------------------`);
      console.log(`📄 [Chunk ${processedCount + 1}/${totalChunks}]: ${chunkDesc}`);

      try {
        // --- TOKEN GUARD: truncate content to stay safely under Groq 12k TPM limit ---
        // System prompt ≈ 2,500 tokens. Reserve 4,096 for LLM output.
        // Safe content budget ≈ 12,000 - 2,500 - 4,096 = 5,404 tokens ≈ 20,535 chars
        const MAX_CONTENT_CHARS = 20000;
        let safeChunk = chunk;
        if (chunk.content && chunk.content.length > MAX_CONTENT_CHARS) {
          const truncated = chunk.content.substring(0, MAX_CONTENT_CHARS);
          const cutLine = (truncated.match(/\n/g) || []).length + 1;
          console.log(`   ↳ ✂️ Content truncated to ${MAX_CONTENT_CHARS} chars (${chunk.content.length} total) to stay within 12k TPM limit`);
          safeChunk = { ...chunk, content: truncated + '\n/* [TRUNCATED FOR TOKEN LIMIT] */', endLine: cutLine };
        }

        const userPrompt = buildUserMessage(safeChunk);
        const startTime = Date.now();

        console.log(`   ↳ 🤖 Sending request to Groq LLaMA 3.3 70B...`);

        const completion = await groq.chat.completions.create({
          messages: [
            { role: 'system', content: PHASE_2_SYSTEM_PROMPT },
            { role: 'user', content: userPrompt }
          ],
          model: modelName,
          temperature: 0.1,
          max_completion_tokens: 4096,
          response_format: { type: 'json_object' }
        });

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
        // NOTE: createdAt must ONLY be in $setOnInsert — never in $set — to avoid
        // MongoDB "path conflict" error when the document already exists on retry.
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
        console.log(`   ↳ 🎯 Extracted ${normalizedNodes.length} Security Nodes & ${normalizedEdges.length} Relationships in ${elapsedTime}ms`);
        if (frameworks.length > 0) {
          console.log(`   ↳ 🧩 Frameworks Detected: ${frameworks.join(', ')}`);
        }
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
