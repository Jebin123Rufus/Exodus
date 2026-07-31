/**
 * Validates 100% character and line coverage of generated semantic chunks against original file code.
 * Guarantees zero skipped regions, zero accidental truncation, original ordering preserved, zero data loss.
 * 
 * @param {string} originalCode - Original source code string
 * @param {Array<Object>} chunks - Generated semantic chunk objects
 * @param {string} filePath - Path of the file being validated
 * @returns {Object} Comprehensive validation report
 */
export function validateChunkCoverage(originalCode, chunks, filePath = 'file') {
  const totalChars = originalCode ? originalCode.length : 0;

  if (totalChars === 0) {
    return {
      isValid: true,
      filePath,
      totalChars: 0,
      coveredChars: 0,
      missingRanges: [],
      charCoveragePercent: 100,
      report: `[Coverage Validation SUCCESS]: ${filePath} is an empty file (0 chars covered).`
    };
  }

  if (!chunks || chunks.length === 0) {
    return {
      isValid: false,
      filePath,
      totalChars,
      coveredChars: 0,
      missingRanges: [{ start: 0, end: totalChars }],
      charCoveragePercent: 0,
      report: `[Coverage Validation FAILURE]: ${filePath} has 0 chunks generated for ${totalChars} chars.`
    };
  }

  const covered = new Uint8Array(totalChars);

  // 1. Verify content fidelity and mark character coverage
  const contentErrors = [];
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const { startOffset, endOffset, content } = chunk;

    // Sanity checks
    if (startOffset < 0 || endOffset > totalChars || startOffset > endOffset) {
      contentErrors.push(`Chunk ${i} bounds invalid: [${startOffset}, ${endOffset}] vs total ${totalChars}`);
      continue;
    }

    const expectedContent = originalCode.slice(startOffset, endOffset);
    if (content !== expectedContent) {
      contentErrors.push(`Chunk ${i} content mismatch at offsets [${startOffset}, ${endOffset}]`);
    }

    // Mark covered offsets
    for (let o = startOffset; o < endOffset; o++) {
      covered[o] = 1;
    }
  }

  // 2. Scan for missing offset gaps
  const missingRanges = [];
  let gapStart = -1;
  let coveredCount = 0;

  for (let i = 0; i < totalChars; i++) {
    if (covered[i] === 1) {
      coveredCount++;
      if (gapStart !== -1) {
        missingRanges.push({ start: gapStart, end: i });
        gapStart = -1;
      }
    } else {
      if (gapStart === -1) {
        gapStart = i;
      }
    }
  }

  if (gapStart !== -1) {
    missingRanges.push({ start: gapStart, end: totalChars });
  }

  // 3. Verify chunk ordering
  let orderingValid = true;
  for (let i = 0; i < chunks.length - 1; i++) {
    if (chunks[i].startOffset > chunks[i + 1].startOffset) {
      orderingValid = false;
      contentErrors.push(`Chunk ordering violated between chunk ${i} and chunk ${i + 1}`);
    }
  }

  const charCoveragePercent = (coveredCount / totalChars) * 100;
  const isValid = missingRanges.length === 0 && contentErrors.length === 0 && orderingValid;

  const reportLines = [
    `=== Coverage Validation Report for ${filePath} ===`,
    `Status: ${isValid ? 'PASSED' : 'FAILED'}`,
    `Total Characters: ${totalChars}`,
    `Covered Characters: ${coveredCount} (${charCoveragePercent.toFixed(2)}%)`,
    `Total Chunks: ${chunks.length}`,
    `Missing Gaps Count: ${missingRanges.length}`,
    `Content Mismatches: ${contentErrors.length}`
  ];

  if (missingRanges.length > 0) {
    reportLines.push(`Missing Offset Ranges: ${JSON.stringify(missingRanges.slice(0, 5))}`);
  }
  if (contentErrors.length > 0) {
    reportLines.push(`Validation Errors: ${contentErrors.join('; ')}`);
  }

  return {
    isValid,
    filePath,
    totalChars,
    coveredChars: coveredCount,
    missingRanges,
    contentErrors,
    charCoveragePercent,
    report: reportLines.join('\n')
  };
}
