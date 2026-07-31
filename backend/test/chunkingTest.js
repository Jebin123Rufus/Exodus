import { parseSourceCode } from '../src/chunking/languageParser.js';
import { generateSemanticChunks } from '../src/chunking/semanticChunker.js';
import { validateChunkCoverage } from '../src/chunking/coverageValidator.js';
import { generateDeterministicChunkId } from '../src/chunking/chunkWriter.js';
import { estimateTokens } from '../src/chunking/tokenEstimator.js';

async function runChunkingTests() {
  console.log('==================================================');
  console.log('RUNNING SEMANTIC CHUNKING SERVICE TEST SUITE');
  console.log('==================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  // TEST 1: React TypeScript AST Parsing & Chunking
  const reactTsCode = `import React, { useState, useEffect } from 'react';

export interface UserProps {
  id: string;
  name: string;
}

export const UserCard: React.FC<UserProps> = ({ id, name }) => {
  const [active, setActive] = useState<boolean>(false);

  useEffect(() => {
    console.log("User card mounted", id);
    return () => console.log("User card unmounted");
  }, [id]);

  const handleClick = () => {
    setActive(!active);
  };

  return (
    <div className="user-card" onClick={handleClick}>
      <h3>{name}</h3>
      <p>Status: {active ? 'Active' : 'Inactive'}</p>
    </div>
  );
};

export function computeUserScore(points: number[]): number {
  let score = 0;
  for (const p of points) {
    score += p;
  }
  return score;
}
`;

  console.log('--- Test 1: React TypeScript AST Parsing & Chunking ---');
  const parseResult1 = parseSourceCode(reactTsCode, 'src/components/UserCard.tsx');
  assert(parseResult1.parseType === 'babel', 'Babel parser successfully selected for TSX file');
  assert(parseResult1.language === 'typescript', 'Language correctly detected as typescript');

  const chunks1 = generateSemanticChunks(reactTsCode, parseResult1, { targetContext: 1000 });
  assert(chunks1.length > 0, `Generated ${chunks1.length} chunk(s) for React component`);

  const report1 = validateChunkCoverage(reactTsCode, chunks1, 'src/components/UserCard.tsx');
  assert(report1.isValid, `Coverage validation PASSED: ${report1.charCoveragePercent}% covered`);

  // TEST 2: Oversized Function Recursive AST Decomposition
  console.log('\n--- Test 2: Oversized Function Recursive AST Decomposition ---');
  let largeFuncCode = `import { processData } from './utils';\n\nexport function massiveFunction() {\n`;
  for (let i = 1; i <= 100; i++) {
    largeFuncCode += `  const var_${i} = "Data line ${i} with extra text to consume token budget";\n`;
    largeFuncCode += `  if (var_${i}.length > 10) {\n    console.log("Processing item ${i}");\n  }\n`;
  }
  largeFuncCode += `  return "done";\n}\n`;

  const parseResult2 = parseSourceCode(largeFuncCode, 'src/services/heavyService.ts');
  // Enforce tight targetContext to force chunking across function body
  const chunks2 = generateSemanticChunks(largeFuncCode, parseResult2, { targetContext: 200, reservePercentage: 0.1 });
  assert(chunks2.length > 1, `Massive function split into ${chunks2.length} semantic chunks`);

  const report2 = validateChunkCoverage(largeFuncCode, chunks2, 'src/services/heavyService.ts');
  assert(report2.isValid, `Coverage validation PASSED for decomposed function (${report2.charCoveragePercent}% covered)`);

  // TEST 3: Structural Parser Fallback (Python Code)
  console.log('\n--- Test 3: Structural Parser Fallback for Python ---');
  const pythonCode = `import os
import sys

class DataProcessor:
    def __init__(self, filename):
        self.filename = filename

    def process(self):
        if not os.path.exists(self.filename):
            raise FileNotFoundError("File missing")
        with open(self.filename, 'r') as f:
            return f.read()

def main():
    processor = DataProcessor("config.json")
    print(processor.process())

if __name__ == "__main__":
    main()
`;

  const parseResult3 = parseSourceCode(pythonCode, 'scripts/processor.py');
  assert(parseResult3.parseType === 'structural', 'Structural block parser selected for Python file');
  assert(parseResult3.language === 'python', 'Language correctly detected as python');

  const chunks3 = generateSemanticChunks(pythonCode, parseResult3, { targetContext: 500 });
  assert(chunks3.length > 0, `Generated ${chunks3.length} chunk(s) for Python script`);

  const report3 = validateChunkCoverage(pythonCode, chunks3, 'scripts/processor.py');
  assert(report3.isValid, `Coverage validation PASSED for Python file (${report3.charCoveragePercent}% covered)`);

  // TEST 4: Deterministic Chunk IDs
  console.log('\n--- Test 4: Deterministic Chunk ID Generation ---');
  const id1 = generateDeterministicChunkId('analysis_123', 'src/App.tsx', 0);
  const id2 = generateDeterministicChunkId('analysis_123', 'src/App.tsx', 0);
  const id3 = generateDeterministicChunkId('analysis_123', 'src/App.tsx', 1);

  assert(id1 === id2, `Identical input produces identical chunk ID (${id1})`);
  assert(id1 !== id3, `Different chunk index produces different chunk ID (${id3})`);

  // TEST 5: Context Overlap Verification
  console.log('\n--- Test 5: Context Overlap Verification ---');
  if (chunks2.length > 1) {
    const chunk0 = chunks2[0];
    const chunk1 = chunks2[1];
    assert(chunk1.startOffset < chunk0.endOffset, `Chunk 1 overlaps into Chunk 0 (start: ${chunk1.startOffset} < end: ${chunk0.endOffset})`);
  }

  console.log('\n==================================================');
  console.log(`TEST SUITE COMPLETE: ${passed} PASSED, ${failed} FAILED`);
  console.log('==================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runChunkingTests().catch((err) => {
  console.error('Test runner encountered unexpected error:', err);
  process.exit(1);
});
