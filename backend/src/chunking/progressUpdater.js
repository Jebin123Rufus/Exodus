/**
 * Updates chunking progress on parent analysis document in MongoDB analysisResults collection.
 * Enables live progress monitoring for backend and frontend clients.
 * 
 * @param {Object} db - MongoDB database instance
 * @param {string} analysisId - Unique analysis identifier
 * @param {Object} progressState - Progress metrics to update
 * @returns {Promise<void>}
 */
export async function updateAnalysisProgress(db, analysisId, progressState) {
  if (!db || !analysisId) return;

  const collection = db.collection('analysisResults');

  const updateFields = {
    updatedAt: new Date(),
    lastChunkedAt: new Date()
  };

  if (progressState.status !== undefined) updateFields.chunkingStatus = progressState.status;
  if (progressState.processedFiles !== undefined) updateFields.processedFiles = progressState.processedFiles;
  if (progressState.completedFiles !== undefined) updateFields.completedFiles = progressState.completedFiles;
  if (progressState.failedFiles !== undefined) updateFields.failedFiles = progressState.failedFiles;
  if (progressState.totalFiles !== undefined) updateFields.totalFilesToChunk = progressState.totalFiles;
  if (progressState.totalChunks !== undefined) updateFields.totalChunks = progressState.totalChunks;
  if (progressState.fileProgress !== undefined) updateFields.fileProgress = progressState.fileProgress;
  if (progressState.lastError !== undefined) updateFields.lastChunkingError = progressState.lastError;

  await collection.updateOne(
    { analysisId },
    { $set: updateFields }
  );
}
