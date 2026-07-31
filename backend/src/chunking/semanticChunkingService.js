import { parseSourceCode } from './languageParser.js';
import { generateSemanticChunks } from './semanticChunker.js';
import { validateChunkCoverage } from './coverageValidator.js';
import { writeSemanticChunks } from './chunkWriter.js';
import { updateAnalysisProgress } from './progressUpdater.js';
import { EvidenceExtractionService } from '../evidence/evidenceExtractionService.js';

/**
 * Main Semantic Chunking Pipeline Orchestrator.
 * Reads stored files from MongoDB, semantically chunks them using ASTs,
 * validates 100% character coverage, stores chunks into `semantic_chunks` collection,
 * and updates analysis progress in real time with high-visibility terminal logs.
 */
export class SemanticChunkingService {
  /**
   * Runs the complete semantic chunking pipeline for an analysis record.
   * 
   * @param {Object} db - MongoDB database instance
   * @param {string} analysisId - ID of analysis record in analysisResults collection
   * @param {Object} [options] - Options (accessToken, owner, repoName, defaultBranch, targetContext, etc.)
   * @returns {Promise<Object>} Summary of chunking execution
   */
  static async processAnalysis(db, analysisId, options = {}) {
    if (!db) throw new Error('[SemanticChunkingService] MongoDB database reference missing.');
    if (!analysisId) throw new Error('[SemanticChunkingService] analysisId parameter is required.');

    // 1. Read parent analysis document from MongoDB
    const analysisCollection = db.collection('analysisResults');
    const analysis = await analysisCollection.findOne({ analysisId });

    if (!analysis) {
      throw new Error(`[SemanticChunkingService] Analysis document not found for analysisId: ${analysisId}`);
    }

    const { repoId, userId, repoFullName, extractedFiles = [] } = analysis;
    const totalFiles = extractedFiles.length;

    console.log(`\n================================================================================`);
    console.log(`🚀 [SEMANTIC CHUNKING SERVICE] Starting Pipeline`);
    console.log(`📌 Analysis ID:   ${analysisId}`);
    console.log(`📦 Repository:    ${repoFullName || options.repoName || 'Codebase'}`);
    console.log(`📄 Total Files:   ${totalFiles}`);
    console.log(`================================================================================\n`);

    // Initialize progress tracking
    const fileProgress = {};
    let processedFiles = 0;
    let completedFiles = 0;
    let failedFiles = 0;
    let totalChunksGenerated = 0;

    await updateAnalysisProgress(db, analysisId, {
      status: 'IN_PROGRESS',
      totalFiles,
      processedFiles: 0,
      completedFiles: 0,
      failedFiles: 0,
      totalChunks: 0,
      fileProgress
    });

    if (totalFiles === 0) {
      console.warn(`⚠️ [SemanticChunkingService] No extracted files found in analysis document for ${analysisId}`);
      await updateAnalysisProgress(db, analysisId, {
        status: 'COMPLETED',
        totalFiles: 0,
        processedFiles: 0,
        completedFiles: 0,
        failedFiles: 0,
        totalChunks: 0
      });
      return { success: true, message: 'No files to process.', totalFiles: 0, totalChunks: 0 };
    }

    const accessToken = options.accessToken;
    const [owner, repoName] = (repoFullName || '').split('/');
    const defaultBranch = options.defaultBranch || 'main';

    // 2. Iterate through each stored file
    for (const fileItem of extractedFiles) {
      let filePath = '';
      let fileContent = '';
      let fileLanguage = null;

      // Support fileItem as string (path) or object { path/filePath, content, language }
      if (typeof fileItem === 'string') {
        filePath = fileItem;
      } else if (typeof fileItem === 'object' && fileItem !== null) {
        filePath = fileItem.path || fileItem.filePath || fileItem.fileName || 'unknown_file';
        fileContent = fileItem.content || fileItem.sourceCode || fileItem.code || '';
        fileLanguage = fileItem.language;
      }

      console.log(`--------------------------------------------------------------------------------`);
      console.log(`📄 [File ${processedFiles + 1}/${totalFiles}]: ${filePath}`);

      // If file content is missing, fetch from GitHub raw endpoint
      if (!fileContent && accessToken && owner && repoName) {
        try {
          const rawUrl = `https://raw.githubusercontent.com/${owner}/${repoName}/${defaultBranch}/${filePath}`;
          console.log(`   ↳ 🌐 Fetching source code from GitHub: ${rawUrl}`);
          const res = await fetch(rawUrl, {
            headers: { Authorization: `Bearer ${accessToken}` }
          });
          if (res.ok) {
            fileContent = await res.text();
            console.log(`   ↳ 📥 Received ${fileContent.length} bytes of source code.`);
          } else {
            console.warn(`   ↳ ⚠️ GitHub fetch returned HTTP ${res.status} for ${filePath}`);
          }
        } catch (fetchErr) {
          console.warn(`   ↳ ⚠️ Failed to fetch file content from GitHub for ${filePath}: ${fetchErr.message}`);
        }
      }

      try {
        // Step A: Parse source code into AST / Structural nodes
        const parseResult = parseSourceCode(fileContent, filePath, fileLanguage);
        console.log(`   ↳ 🧠 AST Parser: ${parseResult.parseType === 'babel' ? '@babel/parser (JavaScript/TypeScript AST)' : 'Structural AST Block Parser'} (${parseResult.language})`);

        // Step B: Generate AST-driven semantic chunks with token budgeting and context overlap
        const chunks = generateSemanticChunks(fileContent, parseResult, options);
        console.log(`   ↳ ✂️ Generated ${chunks.length} semantic AST chunk(s) (Target context: ${options.targetContext || 12000} tokens)`);

        // Step C: Validate 100% character coverage & zero data loss
        const coverageReport = validateChunkCoverage(fileContent, chunks, filePath);
        console.log(`   ↳ ✅ Coverage Validation: ${coverageReport.charCoveragePercent.toFixed(1)}% verified (${coverageReport.coveredChars}/${coverageReport.totalChars} chars, 0 missing gaps)`);

        if (!coverageReport.isValid) {
          console.error(`   ↳ ❌ Coverage validation FAILED for ${filePath}:\n${coverageReport.report}`);
          failedFiles++;
          fileProgress[filePath] = {
            status: 'FAILED',
            error: `Coverage validation failed: ${coverageReport.contentErrors.join('; ')}`,
            chunksCount: 0
          };
        } else {
          // Step D: Write chunks into `semantic_chunks` collection
          const writeResult = await writeSemanticChunks(
            db,
            analysisId,
            repoId,
            userId,
            filePath,
            parseResult.language,
            chunks
          );

          completedFiles++;
          totalChunksGenerated += chunks.length;
          fileProgress[filePath] = {
            status: 'COMPLETED',
            language: parseResult.language,
            chunksCount: chunks.length,
            coveragePercent: coverageReport.charCoveragePercent
          };

          console.log(`   ↳ 💾 Saved ${chunks.length} chunk(s) to MongoDB collection [semantic_chunks]`);
        }
      } catch (fileErr) {
        console.error(`   ↳ ❌ Error processing file ${filePath}:`, fileErr.message);
        failedFiles++;
        fileProgress[filePath] = {
          status: 'FAILED',
          error: fileErr.message,
          chunksCount: 0
        };
      }

      processedFiles++;

      // Step E: Update analysis progress in MongoDB after each file
      await updateAnalysisProgress(db, analysisId, {
        status: 'IN_PROGRESS',
        totalFiles,
        processedFiles,
        completedFiles,
        failedFiles,
        totalChunks: totalChunksGenerated,
        fileProgress
      });
    }

    // 3. Finalize pipeline execution status
    const finalStatus = failedFiles === 0
      ? 'COMPLETED'
      : completedFiles > 0
        ? 'PARTIAL_SUCCESS'
        : 'FAILED';

    await updateAnalysisProgress(db, analysisId, {
      status: finalStatus,
      totalFiles,
      processedFiles,
      completedFiles,
      failedFiles,
      totalChunks: totalChunksGenerated,
      fileProgress
    });

    console.log(`================================================================================`);
    console.log(`🎉 [SEMANTIC CHUNKING SERVICE COMPLETED] Status: ${finalStatus}`);
    console.log(`📊 Summary: ${completedFiles}/${totalFiles} files completed successfully (${failedFiles} failed).`);
    console.log(`📦 Total Chunks Generated & Saved: ${totalChunksGenerated}`);
    console.log(`================================================================================\n`);

    // 4. AUTOMATICALLY TRIGGER PHASE 2 - Security Evidence Extraction Engine
    if (finalStatus !== 'FAILED' && totalChunksGenerated > 0) {
      console.log(`🚀 [PHASE 2 AUTO-TRIGGER] Handing off ${totalChunksGenerated} chunks to SentinelAI Evidence Extraction Engine...\n`);
      EvidenceExtractionService.processAnalysisEvidence(db, analysisId).catch((evidenceErr) => {
        console.error(`❌ [Phase 2 Background Error] Evidence extraction failed for ${analysisId}:`, evidenceErr.message);
      });
    }

    return {
      success: finalStatus !== 'FAILED',
      status: finalStatus,
      analysisId,
      totalFiles,
      completedFiles,
      failedFiles,
      totalChunks: totalChunksGenerated,
      fileProgress
    };
  }
}
