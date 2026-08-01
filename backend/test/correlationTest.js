import dotenv from 'dotenv';
dotenv.config();

import { STAGE_3_SYSTEM_PROMPT, buildReasonerUserMessage } from '../src/correlation/correlationPrompts.js';
import { EvidenceGraph } from '../src/correlation/evidenceGraphBuilder.js';
import { FindingMerger } from '../src/correlation/findingMerger.js';
import { InjectionReasoner } from '../src/correlation/reasoners/domainReasoners.js';
import Groq from 'groq-sdk';

async function runCorrelationTests() {
  console.log('==================================================');
  console.log('RUNNING SENTINELAI STAGE 3 - CORRELATION ENGINE TEST SUITE');
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

  // ---------------------------------------------------------
  // TEST 1: System prompt & message builder validation
  // ---------------------------------------------------------
  console.log('--- Test 1: System Prompt & User Message Builder ---');
  assert(typeof STAGE_3_SYSTEM_PROMPT === 'string' && STAGE_3_SYSTEM_PROMPT.length > 500,
    'Stage 3 System Prompt loaded successfully');
  assert(STAGE_3_SYSTEM_PROMPT.includes('Injection Vulnerabilities'),
    'System Prompt includes Injection Vulnerabilities category');

  const mockUserMsg = buildReasonerUserMessage('InjectionReasoner', [{ id: 'n1', type: 'INPUT_SOURCE' }], []);
  assert(mockUserMsg.includes('InjectionReasoner'), 'User message includes reasoner name');
  assert(mockUserMsg.includes('INPUT_SOURCE'), 'User message includes node evidence');

  // ---------------------------------------------------------
  // TEST 2: In-Memory Evidence Graph Indexing & Subsetting
  // ---------------------------------------------------------
  console.log('\n--- Test 2: In-Memory Evidence Graph Querying ---');
  const sampleNodes = [
    { id: 'server.js:0:n1', type: 'INPUT_SOURCE', file: 'server.js', confidence: 0.9 },
    { id: 'server.js:0:n2', type: 'DATABASE_QUERY', file: 'server.js', confidence: 0.95 },
    { id: 'server.js:0:n3', type: 'AUTHENTICATION', file: 'server.js', confidence: 0.8 }
  ];
  const sampleEdges = [
    { id: 'e1', source: 'server.js:0:n1', relationship: 'FLOWS_TO', target: 'server.js:0:n2', confidence: 0.9 }
  ];

  const graph = new EvidenceGraph(sampleNodes, sampleEdges, ['express'], ['mongoose'], 'test_analysis_1');

  const injectionNodes = graph.getNodesByTypes(['INPUT_SOURCE', 'DATABASE_QUERY']);
  assert(injectionNodes.length === 2, `getNodesByTypes returned 2 nodes (actual: ${injectionNodes.length})`);

  const injectionEdges = graph.getEdgesForNodes(new Set(injectionNodes.map((n) => n.id)));
  assert(injectionEdges.length === 1, `getEdgesForNodes returned 1 edge (actual: ${injectionEdges.length})`);

  // ---------------------------------------------------------
  // TEST 3: Finding Merger Deduplication & Confidence Calculation
  // ---------------------------------------------------------
  console.log('\n--- Test 3: Finding Merger & Deduplicator ---');
  const rawFindings = [
    {
      title: 'SQL Injection via Query Parameter',
      category: 'Injection Vulnerabilities',
      severity: 'HIGH',
      confidence: 0.8,
      affected_files: ['server.js'],
      evidence_node_ids: ['server.js:0:n1', 'server.js:0:n2'],
      reasoning: 'User input flows into unparameterized database query.',
      reasoner: 'InjectionReasoner'
    },
    {
      title: 'SQL Injection via Query Parameter',
      category: 'Injection Vulnerabilities',
      severity: 'HIGH',
      confidence: 0.85,
      affected_files: ['server.js'],
      evidence_node_ids: ['server.js:0:n2'],
      reasoning: 'Same finding reported by another reasoner.',
      reasoner: 'BusinessLogicReasoner'
    }
  ];

  const merged = FindingMerger.mergeFindings(rawFindings, graph);
  assert(merged.length === 1, `Deduplicated 2 raw findings into 1 merged finding (actual: ${merged.length})`);
  assert(merged[0].finding_id.startsWith('fnd_'), `Finding ID generated with prefix 'fnd_' (${merged[0].finding_id})`);
  assert(merged[0].evidence_node_ids.length === 2, 'Merged finding combines unique node IDs');

  // ---------------------------------------------------------
  // TEST 4: GROQ_LLAMA_PHASE_3 API Key & Live Stage 3 Reasoning
  // ---------------------------------------------------------
  console.log('\n--- Test 4: GROQ_LLAMA_PHASE_3 Key & Live Reasoner Call ---');
  const apiKey = process.env.GROQ_LLAMA_PHASE_3;
  assert(typeof apiKey === 'string' && apiKey.length > 10,
    `GROQ_LLAMA_PHASE_3 API Key loaded from .env (length: ${apiKey?.length})`);

  const reasoner = new InjectionReasoner();
  try {
    const findings = await reasoner.analyze(graph);
    assert(Array.isArray(findings), 'InjectionReasoner returned array of findings');
    console.log(`   ↳ Extracted ${findings.length} finding(s) from sample evidence graph`);
  } catch (err) {
    assert(false, `InjectionReasoner analysis failed: ${err.message}`);
  }

  console.log('\n==================================================');
  console.log(`TEST SUITE COMPLETE: ${passed} PASSED, ${failed} FAILED`);
  console.log('==================================================\n');

  if (failed > 0) process.exit(1);
}

runCorrelationTests().catch((err) => {
  console.error('Stage 3 test runner error:', err);
  process.exit(1);
});
