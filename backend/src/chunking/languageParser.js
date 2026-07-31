import { parse } from '@babel/parser';

/**
 * Maps file path/extension to language identifier.
 * @param {string} filePath 
 * @returns {string} Normalized language identifier
 */
export function detectLanguage(filePath) {
  if (!filePath) return 'plaintext';
  const ext = filePath.split('.').pop()?.toLowerCase() || '';

  const extMap = {
    js: 'javascript',
    jsx: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    ts: 'typescript',
    tsx: 'typescript',
    py: 'python',
    pyw: 'python',
    java: 'java',
    go: 'go',
    rs: 'rust',
    cpp: 'cpp',
    c: 'c',
    h: 'c',
    hpp: 'cpp',
    cs: 'csharp',
    php: 'php',
    rb: 'ruby',
    swift: 'swift',
    kt: 'kotlin',
    html: 'html',
    htm: 'html',
    css: 'css',
    scss: 'scss',
    json: 'json',
    yaml: 'yaml',
    yml: 'yaml',
    md: 'markdown',
    sql: 'sql',
    sh: 'bash',
    bash: 'bash'
  };

  return extMap[ext] || 'plaintext';
}

/**
 * Checks if a language is supported by Babel AST parser.
 * @param {string} language 
 * @returns {boolean}
 */
export function isBabelSupported(language) {
  return ['javascript', 'typescript'].includes(language);
}

/**
 * Parses source code into AST or structural block tree.
 * @param {string} code 
 * @param {string} filePath 
 * @param {string} [overrideLanguage] 
 * @returns {Object} Parse result containing language, parseType ('babel'|'structural'), ast/nodes, and sourceCode
 */
export function parseSourceCode(code, filePath, overrideLanguage) {
  const language = overrideLanguage || detectLanguage(filePath);

  if (isBabelSupported(language)) {
    try {
      const isTypeScript = filePath.endsWith('.ts') || filePath.endsWith('.tsx');
      const isJsx = filePath.endsWith('.jsx') || filePath.endsWith('.tsx') || filePath.endsWith('.js');

      const plugins = [
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'decorators-legacy',
        'dynamicImport',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'nullishCoalescingOperator',
        'optionalChaining',
        'objectRestSpread',
        'topLevelAwait',
        'asyncGenerators',
        'doExpressions',
        'functionBind'
      ];

      if (isJsx) plugins.push('jsx');
      if (isTypeScript) plugins.push('typescript');

      const ast = parse(code, {
        sourceType: 'module',
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        tokens: true,
        plugins
      });

      return {
        success: true,
        parseType: 'babel',
        language,
        ast,
        sourceCode: code
      };
    } catch (babelErr) {
      console.warn(`[LanguageParser] Babel parser failed for ${filePath}: ${babelErr.message}. Falling back to structural block parser.`);
    }
  }

  // Structural AST block parser fallback for Python, HTML, Java, Go, Markdown, JSON, etc.
  const nodes = parseStructuralBlocks(code, language);
  return {
    success: true,
    parseType: 'structural',
    language,
    nodes,
    sourceCode: code
  };
}

/**
 * Generates line offset index array for converting character index to line/col.
 * @param {string} text 
 * @returns {number[]} Array of start character offsets for each line (1-indexed)
 */
export function getLineOffsets(text) {
  const offsets = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') {
      offsets.push(i + 1);
    }
  }
  return offsets;
}

/**
 * Converts character offset to 1-based line number.
 * @param {number[]} lineOffsets 
 * @param {number} offset 
 * @returns {number} 1-based line number
 */
export function offsetToLine(lineOffsets, offset) {
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    if (lineOffsets[mid] <= offset) {
      if (mid === lineOffsets.length - 1 || lineOffsets[mid + 1] > offset) {
        return mid + 1;
      }
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return 1;
}

/**
 * Structural AST block parser for non-JS languages or fallback.
 * Identifies block boundaries (imports, classes, functions, control blocks, headers) with offsets & lines.
 * @param {string} code 
 * @param {string} language 
 * @returns {Array<Object>} List of top-level structural nodes
 */
export function parseStructuralBlocks(code, language) {
  const lines = code.split('\n');
  const lineOffsets = getLineOffsets(code);
  const nodes = [];

  let currentBlock = null;

  const pushCurrentBlock = (endLineIdx) => {
    if (!currentBlock) return;
    const endLine = endLineIdx + 1;
    const startOffset = lineOffsets[currentBlock.startLine - 1] ?? 0;
    const nextLineOffset = lineOffsets[endLine] ?? code.length;
    const endOffset = (endLineIdx < lines.length - 1) ? lineOffsets[endLineIdx + 1] - 1 : code.length;

    currentBlock.endLine = endLine;
    currentBlock.startOffset = startOffset;
    currentBlock.endOffset = Math.min(code.length, Math.max(startOffset, endOffset));
    nodes.push(currentBlock);
    currentBlock = null;
  };

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    const trimmed = line.trim();

    // Check for structural block header keywords
    const isImport = /^(import\s|from\s|package\s|include\s|require\(|#include)/i.test(trimmed);
    const isClassOrStruct = /^(class\s|struct\s|interface\s|enum\s|type\s|def\s|func\s|function\s|public\s+class|private\s+class|protected\s+class)/i.test(trimmed);
    const isHeader = /^#{1,6}\s/.test(trimmed); // Markdown headers

    if (isImport) {
      if (currentBlock && currentBlock.type !== 'Import') {
        pushCurrentBlock(idx - 1);
      }
      if (!currentBlock) {
        currentBlock = { type: 'Import', name: trimmed, startLine: lineNum };
      }
    } else if (isClassOrStruct || isHeader) {
      if (currentBlock) {
        pushCurrentBlock(idx - 1);
      }
      currentBlock = {
        type: isHeader ? 'Section' : 'Block',
        name: trimmed.substring(0, 80),
        startLine: lineNum
      };
    } else if (trimmed === '' && currentBlock && currentBlock.type === 'Import') {
      pushCurrentBlock(idx - 1);
    } else if (!currentBlock) {
      currentBlock = {
        type: 'Block',
        name: trimmed.substring(0, 80) || `Line ${lineNum}`,
        startLine: lineNum
      };
    }
  });

  if (currentBlock) {
    pushCurrentBlock(lines.length - 1);
  }

  // If no blocks were created (empty file or single line)
  if (nodes.length === 0 && code.length > 0) {
    nodes.push({
      type: 'Block',
      name: 'FullContent',
      startLine: 1,
      endLine: lines.length,
      startOffset: 0,
      endOffset: code.length
    });
  }

  return nodes;
}
