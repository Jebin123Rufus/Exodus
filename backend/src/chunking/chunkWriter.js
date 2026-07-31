import crypto from 'crypto';

/**
 * Generates a deterministic Chunk ID for a given analysis, file path, and index.
 * The same file always produces identical chunk IDs.
 * 
 * @param {string} analysisId 
 * @param {string} filePath 
 * @param {number} chunkIndex 
 * @returns {string} Deterministic chunkId hash string
 */
export function generateDeterministicChunkId(analysisId, filePath, chunkIndex) {
  const hash = crypto
    .createHash('sha256')
    .update(`${analysisId}:${filePath}:${chunkIndex}`)
    .digest('hex')
    .substring(0, 24);
  return `chk_${hash}`;
}

/**
 * Stores generated semantic chunks into MongoDB `semantic_chunks` collection.
 * Performs upserts using bulkWrite for idempotent execution.
 * 
 * @param {Object} db - MongoDB database instance
 * @param {string} analysisId 
 * @param {string} repositoryId 
 * @param {string} userId 
 * @param {string} filePath 
 * @param {string} language 
 * @param {Array<Object>} chunks - List of generated chunk objects
 * @returns {Promise<Object>} Summary of operations (inserted, updated, total)
 */
export async function writeSemanticChunks(db, analysisId, repositoryId, userId, filePath, language, chunks) {
  if (!db) throw new Error('[ChunkWriter] MongoDB database instance is required.');
  if (!chunks || chunks.length === 0) return { count: 0 };

  const collection = db.collection('semantic_chunks');
  const now = new Date();

  const operations = chunks.map((chunk) => {
    const chunkId = generateDeterministicChunkId(analysisId, filePath, chunk.chunkIndex);

    const doc = {
      analysisId,
      repositoryId: repositoryId ? repositoryId.toString() : null,
      userId: userId ? userId.toString() : null,
      filePath,
      language: language || 'plaintext',
      chunkId,
      chunkIndex: chunk.chunkIndex,
      totalChunks: chunk.totalChunks,
      startLine: chunk.startLine,
      endLine: chunk.endLine,
      startOffset: chunk.startOffset,
      endOffset: chunk.endOffset,
      estimatedTokens: chunk.estimatedTokens,
      status: 'PENDING',
      content: chunk.content,
      updatedAt: now
    };

    return {
      updateOne: {
        filter: { analysisId, filePath, chunkIndex: chunk.chunkIndex },
        update: {
          $set: doc,
          $setOnInsert: { createdAt: now }
        },
        upsert: true
      }
    };
  });

  const result = await collection.bulkWrite(operations, { ordered: false });

  return {
    count: chunks.length,
    upsertedCount: result.upsertedCount || 0,
    modifiedCount: result.modifiedCount || 0,
    insertedCount: result.insertedCount || 0
  };
}
