import { estimateTokens, calculateMaxChunkTokens } from './tokenEstimator.js';
import { getLineOffsets, offsetToLine } from './languageParser.js';

/**
 * Default chunking configuration options.
 */
const DEFAULT_OPTIONS = {
  targetContext: 12000,
  reservePercentage: 0.20,
  overlapRatio: 0.15 // 15% overlap between adjacent chunks
};

/**
 * Extracts semantic AST node ranges from a Babel AST.
 * @param {Object} ast - Babel AST object
 * @param {string} sourceCode - Full file content
 * @returns {Array<Object>} Semantic units with type, start, end, loc, tokens
 */
function extractBabelSemanticNodes(ast, sourceCode) {
  const body = ast.program?.body || [];
  const nodes = [];

  for (const node of body) {
    if (typeof node.start === 'number' && typeof node.end === 'number') {
      const codeSnippet = sourceCode.slice(node.start, node.end);
      nodes.push({
        type: categorizeBabelNodeType(node),
        astNode: node,
        start: node.start,
        end: node.end,
        loc: node.loc,
        tokens: estimateTokens(codeSnippet)
      });
    }
  }

  return nodes;
}

/**
 * Categorizes Babel AST node type into human/semantic category.
 * @param {Object} node 
 * @returns {string}
 */
function categorizeBabelNodeType(node) {
  if (!node) return 'Statement';
  switch (node.type) {
    case 'ImportDeclaration':
      return 'Import';
    case 'ExportNamedDeclaration':
    case 'ExportDefaultDeclaration':
    case 'ExportAllDeclaration':
      return 'Export';
    case 'FunctionDeclaration':
      return 'Function';
    case 'ClassDeclaration':
      return 'Class';
    case 'VariableDeclaration': {
      // Check if variable declaration defines a React component or Arrow Function
      const init = node.declarations?.[0]?.init;
      if (init && (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression')) {
        return 'FunctionalComponent';
      }
      return 'VariableDeclaration';
    }
    case 'IfStatement':
      return 'IfStatement';
    case 'SwitchStatement':
      return 'SwitchStatement';
    case 'TryStatement':
      return 'TryStatement';
    case 'ForStatement':
    case 'ForInStatement':
    case 'ForOfStatement':
    case 'WhileStatement':
    case 'DoWhileStatement':
      return 'Loop';
    case 'BlockStatement':
      return 'BlockScope';
    default:
      return 'Statement';
  }
}

/**
 * Recursively decomposes an oversized Babel AST node into child semantic nodes.
 * Used when a single function or class exceeds the max token limit.
 * @param {Object} parentNode - Parent AST node unit
 * @param {string} sourceCode - Full file source code
 * @param {number} maxTokens - Token budget threshold
 * @returns {Array<Object>} Array of sub-nodes
 */
function decomposeOversizedBabelNode(parentNode, sourceCode, maxTokens) {
  const astNode = parentNode.astNode;
  if (!astNode) return [parentNode];

  const childAstNodes = [];

  // If node is a function or method, extract parameters/header and body statements
  if (astNode.body && astNode.body.type === 'BlockStatement') {
    const blockBody = astNode.body.body || [];
    for (const child of blockBody) {
      if (typeof child.start === 'number' && typeof child.end === 'number') {
        const snippet = sourceCode.slice(child.start, child.end);
        childAstNodes.push({
          type: categorizeBabelNodeType(child),
          astNode: child,
          start: child.start,
          end: child.end,
          loc: child.loc,
          tokens: estimateTokens(snippet)
        });
      }
    }
  } else if (astNode.type === 'ClassDeclaration' && astNode.body?.body) {
    // Class methods, constructors, fields
    for (const member of astNode.body.body) {
      if (typeof member.start === 'number' && typeof member.end === 'number') {
        const snippet = sourceCode.slice(member.start, member.end);
        childAstNodes.push({
          type: member.kind === 'constructor' ? 'Constructor' : 'Method',
          astNode: member,
          start: member.start,
          end: member.end,
          loc: member.loc,
          tokens: estimateTokens(snippet)
        });
      }
    }
  }

  // If child nodes were successfully extracted, process them recursively
  if (childAstNodes.length > 0) {
    const result = [];
    for (const child of childAstNodes) {
      if (child.tokens > maxTokens) {
        result.push(...decomposeOversizedBabelNode(child, sourceCode, maxTokens));
      } else {
        result.push(child);
      }
    }
    return result;
  }

  // Leaf node still exceeds maxTokens: return as is (will be split by fallback token windowing)
  return [parentNode];
}

/**
 * Main Semantic Chunk Generator.
 * Generates deterministic semantic chunks with complete coverage and overlap.
 * @param {string} sourceCode - Source code content
 * @param {Object} parseResult - Result object from parseSourceCode
 * @param {Object} [userOptions] - Configuration options
 * @returns {Array<Object>} Generated chunk objects
 */
export function generateSemanticChunks(sourceCode, parseResult, userOptions = {}) {
  const options = { ...DEFAULT_OPTIONS, ...userOptions };
  const maxTokens = calculateMaxChunkTokens(options.targetContext, options.reservePercentage);
  const lineOffsets = getLineOffsets(sourceCode);
  const totalLength = sourceCode.length;

  if (totalLength === 0) {
    return [{
      chunkIndex: 0,
      totalChunks: 1,
      startLine: 1,
      endLine: 1,
      startOffset: 0,
      endOffset: 0,
      estimatedTokens: 0,
      content: ''
    }];
  }

  // 1. Gather semantic nodes
  let rawNodes = [];
  if (parseResult.parseType === 'babel' && parseResult.ast) {
    rawNodes = extractBabelSemanticNodes(parseResult.ast, sourceCode);
  } else if (parseResult.nodes && parseResult.nodes.length > 0) {
    // Structural block nodes
    rawNodes = parseResult.nodes.map((n) => ({
      type: n.type,
      start: n.startOffset,
      end: n.endOffset,
      loc: {
        start: { line: n.startLine },
        end: { line: n.endLine }
      },
      tokens: estimateTokens(sourceCode.slice(n.startOffset, n.endOffset))
    }));
  }

  // Ensure nodes cover from index 0 to totalLength without gaps
  const nodes = fillOffsetGaps(rawNodes, sourceCode, lineOffsets);

  // 2. Decompose any individual nodes that exceed maxTokens budget
  const decomposedNodes = [];
  for (const node of nodes) {
    if (node.tokens > maxTokens) {
      const subNodes = decomposeOversizedBabelNode(node, sourceCode, maxTokens);
      decomposedNodes.push(...subNodes);
    } else {
      decomposedNodes.push(node);
    }
  }

  // Guarantee gap filling again after decomposition
  const finalNodes = fillOffsetGaps(decomposedNodes, sourceCode, lineOffsets);

  // 3. Group nodes into chunk ranges respecting maxTokens budget
  const chunkRanges = [];
  let currentGroup = [];
  let currentGroupTokens = 0;
  let currentGroupStart = 0;

  for (let i = 0; i < finalNodes.length; i++) {
    const node = finalNodes[i];
    const nodeTokens = node.tokens || estimateTokens(sourceCode.slice(node.start, node.end));

    // Handle single node larger than maxTokens budget (fallback windowing)
    if (nodeTokens > maxTokens && currentGroup.length === 0) {
      const windowChunks = splitOversizedRange(node.start, node.end, sourceCode, maxTokens, lineOffsets);
      chunkRanges.push(...windowChunks);
      currentGroupStart = node.end;
      continue;
    }

    if (currentGroupTokens + nodeTokens > maxTokens && currentGroup.length > 0) {
      // Finalize current chunk range
      const endOffset = currentGroup[currentGroup.length - 1].end;
      chunkRanges.push({ startOffset: currentGroupStart, endOffset });

      // Start next chunk group
      currentGroup = [node];
      currentGroupTokens = nodeTokens;
      currentGroupStart = node.start;
    } else {
      if (currentGroup.length === 0) {
        currentGroupStart = node.start;
      }
      currentGroup.push(node);
      currentGroupTokens += nodeTokens;
    }
  }

  if (currentGroup.length > 0) {
    const endOffset = currentGroup[currentGroup.length - 1].end;
    chunkRanges.push({ startOffset: currentGroupStart, endOffset });
  }

  // Ensure exact coverage spanning 0 to totalLength
  ensureFullCoverageRanges(chunkRanges, totalLength);

  // 4. Apply 10-20% Context Overlap between adjacent chunks
  const overlappedRanges = applyChunkOverlap(chunkRanges, sourceCode, options.overlapRatio, lineOffsets);

  // 5. Build final Chunk Objects
  const totalChunks = overlappedRanges.length;
  const chunks = overlappedRanges.map((range, idx) => {
    const content = sourceCode.slice(range.startOffset, range.endOffset);
    const startLine = offsetToLine(lineOffsets, range.startOffset);
    const endLine = offsetToLine(lineOffsets, Math.max(range.startOffset, range.endOffset - 1));
    const estimatedTokens = estimateTokens(content);

    return {
      chunkIndex: idx,
      totalChunks,
      startLine,
      endLine,
      startOffset: range.startOffset,
      endOffset: range.endOffset,
      estimatedTokens,
      content
    };
  });

  return chunks;
}

/**
 * Fills any gap regions between AST nodes to guarantee continuous character offsets.
 */
function fillOffsetGaps(nodes, sourceCode, lineOffsets) {
  if (nodes.length === 0) {
    return [{
      type: 'FullCode',
      start: 0,
      end: sourceCode.length,
      tokens: estimateTokens(sourceCode)
    }];
  }

  // Sort nodes by start offset
  nodes.sort((a, b) => a.start - b.start);

  const filled = [];
  let cursor = 0;

  for (const node of nodes) {
    if (node.start > cursor) {
      // Gap found: create gap node
      const gapSnippet = sourceCode.slice(cursor, node.start);
      filled.push({
        type: 'Gap',
        start: cursor,
        end: node.start,
        tokens: estimateTokens(gapSnippet)
      });
    }

    // Adjust overlapping AST nodes
    const adjustedStart = Math.max(cursor, node.start);
    const adjustedEnd = Math.max(adjustedStart, node.end);
    const snippet = sourceCode.slice(adjustedStart, adjustedEnd);

    filled.push({
      ...node,
      start: adjustedStart,
      end: adjustedEnd,
      tokens: estimateTokens(snippet)
    });

    cursor = adjustedEnd;
  }

  if (cursor < sourceCode.length) {
    const gapSnippet = sourceCode.slice(cursor, sourceCode.length);
    filled.push({
      type: 'Gap',
      start: cursor,
      end: sourceCode.length,
      tokens: estimateTokens(gapSnippet)
    });
  }

  return filled;
}

/**
 * Splits an oversized range using line/token windowing fallback.
 */
function splitOversizedRange(startOffset, endOffset, sourceCode, maxTokens, lineOffsets) {
  const ranges = [];
  let cursor = startOffset;

  while (cursor < endOffset) {
    const remainingText = sourceCode.slice(cursor, endOffset);
    const remainingTokens = estimateTokens(remainingText);

    if (remainingTokens <= maxTokens) {
      ranges.push({ startOffset: cursor, endOffset });
      break;
    }

    // Estimate character cut point
    const targetChars = Math.floor(maxTokens * 3.8);
    let cutOffset = Math.min(endOffset, cursor + targetChars);

    // Try to cut at newline
    const nextNewline = sourceCode.indexOf('\n', cutOffset);
    const prevNewline = sourceCode.lastIndexOf('\n', cutOffset);

    if (prevNewline > cursor && (cutOffset - prevNewline) < 200) {
      cutOffset = prevNewline + 1;
    } else if (nextNewline !== -1 && nextNewline < endOffset && (nextNewline - cutOffset) < 200) {
      cutOffset = nextNewline + 1;
    }

    if (cutOffset <= cursor) {
      cutOffset = cursor + Math.min(1000, endOffset - cursor);
    }

    ranges.push({ startOffset: cursor, endOffset: cutOffset });
    cursor = cutOffset;
  }

  return ranges;
}

/**
 * Ensures chunk ranges sequentially cover 0 to totalLength.
 */
function ensureFullCoverageRanges(ranges, totalLength) {
  if (ranges.length === 0) {
    ranges.push({ startOffset: 0, endOffset: totalLength });
    return;
  }

  ranges[0].startOffset = 0;
  ranges[ranges.length - 1].endOffset = totalLength;

  for (let i = 0; i < ranges.length - 1; i++) {
    if (ranges[i].endOffset < ranges[i + 1].startOffset) {
      ranges[i].endOffset = ranges[i + 1].startOffset;
    }
  }
}

/**
 * Applies 10-20% context overlap to adjacent chunks.
 */
function applyChunkOverlap(ranges, sourceCode, overlapRatio, lineOffsets) {
  if (ranges.length <= 1) return ranges;

  const result = [];

  for (let i = 0; i < ranges.length; i++) {
    let { startOffset, endOffset } = ranges[i];

    if (i > 0) {
      // Overlap with previous chunk's end
      const prevRange = ranges[i - 1];
      const prevLength = prevRange.endOffset - prevRange.startOffset;
      const overlapChars = Math.floor(prevLength * overlapRatio);

      const targetOverlapStart = Math.max(prevRange.startOffset, prevRange.endOffset - overlapChars);
      
      // Snap overlap start to line beginning for clean execution context
      const overlapLine = offsetToLine(lineOffsets, targetOverlapStart);
      const lineStartOffset = lineOffsets[overlapLine - 1] ?? targetOverlapStart;

      startOffset = Math.min(startOffset, lineStartOffset);
    }

    result.push({ startOffset, endOffset });
  }

  return result;
}
