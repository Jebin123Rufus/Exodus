import { getEncoding } from 'js-tiktoken';

let encoder = null;

try {
  encoder = getEncoding('cl100k_base');
} catch (err) {
  console.warn('[TokenEstimator] Failed to initialize cl100k_base encoder from js-tiktoken, using fallback char ratio estimation:', err.message);
}

/**
 * Estimates token count for a string using BPE tokenizer or character ratio fallback.
 * @param {string} text - Source code or text content
 * @returns {number} Estimated token count
 */
export function estimateTokens(text) {
  if (!text || typeof text !== 'string') return 0;
  if (encoder) {
    try {
      return encoder.encode(text).length;
    } catch (e) {
      // Fallback if encode encounters unexpected characters
    }
  }
  // Heuristic fallback for source code (~3.7 - 4 chars per token)
  return Math.ceil(text.length / 3.8);
}

/**
 * Returns target max tokens for a given budget context.
 * Default budget: 12,000 tokens total, ~20% reserved for LLM prompts/outputs -> 9,600 max per chunk.
 * @param {number} [targetContext=12000] 
 * @param {number} [reservePercentage=0.2] 
 * @returns {number} Max token budget for a single chunk
 */
export function calculateMaxChunkTokens(targetContext = 12000, reservePercentage = 0.2) {
  return Math.floor(targetContext * (1 - reservePercentage));
}
