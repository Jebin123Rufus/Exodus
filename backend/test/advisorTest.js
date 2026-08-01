import dotenv from 'dotenv';
dotenv.config();

import { PHASE_4_SYSTEM_PROMPT, buildAdvisorUserMessage } from '../src/advisor/advisorPrompts.js';
import Groq from 'groq-sdk';

async function runAdvisorTests() {
  console.log('==================================================');
  console.log('RUNNING SENTINELAI PHASE 4 - SECURITY ADVISOR TEST SUITE');
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
  // TEST 1: System prompt & user message builder validation
  // ---------------------------------------------------------
  console.log('--- Test 1: System Prompt & User Message Builder ---');
  assert(typeof PHASE_4_SYSTEM_PROMPT === 'string' && PHASE_4_SYSTEM_PROMPT.length > 500,
    'Phase 4 System Prompt loaded successfully');
  assert(PHASE_4_SYSTEM_PROMPT.includes('executive_summary'),
    'System Prompt includes executive_summary section');
  assert(PHASE_4_SYSTEM_PROMPT.includes('secure_code_fix'),
    'System Prompt includes secure_code_fix section');

  const sampleFinding = {
    finding_id: 'fnd_sample123',
    category: 'Injection Vulnerabilities',
    title: 'Unparameterized SQL Query',
    severity: 'HIGH',
    confidence: 0.90,
    affected_files: ['server/db.js'],
    evidence_node_ids: ['server/db.js:0:n1'],
    description: 'User input concatenation in DB query',
    reasoning: 'Input parameter passed directly to raw query statement',
    attack_path: ['INPUT_SOURCE -> RAW_SQL']
  };

  const sampleNodes = [
    { id: 'server/db.js:0:n1', type: 'RAW_SQL', file: 'server/db.js', start_line: 14, code: 'db.query("SELECT * FROM users WHERE name = " + req.body.name)' }
  ];

  const userMsg = buildAdvisorUserMessage(sampleFinding, sampleNodes);
  assert(userMsg.includes('fnd_sample123'), 'User message includes finding ID');
  assert(userMsg.includes('Unparameterized SQL Query'), 'User message includes finding title');

  // ---------------------------------------------------------
  // TEST 2: GROQ_LLAMA_PHASE_4 API Key & Groq Client Setup
  // ---------------------------------------------------------
  console.log('\n--- Test 2: GROQ_LLAMA_PHASE_4 Key & Client ---');
  const apiKey = process.env.GROQ_LLAMA_PHASE_4;
  assert(typeof apiKey === 'string' && apiKey.length > 10,
    `GROQ_LLAMA_PHASE_4 API Key loaded from .env (length: ${apiKey?.length})`);

  let groqClient = null;
  try {
    groqClient = new Groq({ apiKey });
    assert(groqClient !== null, 'Groq SDK client initialized with GROQ_LLAMA_PHASE_4 key');
  } catch (err) {
    assert(false, `Groq SDK client init failed: ${err.message}`);
  }

  // ---------------------------------------------------------
  // TEST 3: Live Groq Phase 4 LLM Finding Enrichment
  // ---------------------------------------------------------
  console.log('\n--- Test 3: Live Groq Phase 4 Finding Enrichment ---');
  if (groqClient) {
    try {
      const startTime = Date.now();
      const completion = await groqClient.chat.completions.create({
        messages: [
          { role: 'system', content: PHASE_4_SYSTEM_PROMPT },
          { role: 'user', content: userMsg }
        ],
        model: 'llama-3.3-70b-versatile',
        temperature: 0.1,
        max_completion_tokens: 2048,
        response_format: { type: 'json_object' }
      });

      const elapsedTime = Date.now() - startTime;
      const rawContent = completion.choices[0]?.message?.content || '{}';
      assert(typeof rawContent === 'string' && rawContent.length > 0, 'Groq returned non-empty response');

      let parsed;
      try {
        parsed = JSON.parse(rawContent);
      } catch (jsonErr) {
        assert(false, `Groq response is valid JSON: ${jsonErr.message}`);
        parsed = null;
      }

      if (parsed) {
        assert(typeof parsed.executive_summary === 'string', 'Enriched output contains executive_summary');
        assert(typeof parsed.secure_code_fix === 'string', 'Enriched output contains secure_code_fix');
        assert(typeof parsed.fix_explanation === 'string', 'Enriched output contains fix_explanation');
        console.log(`   ↳ Enriched finding in ${elapsedTime}ms`);
        console.log(`   ↳ Executive Summary: "${parsed.executive_summary.substring(0, 80)}..."`);
      }
    } catch (apiErr) {
      assert(false, `Groq API call failed: ${apiErr.message}`);
    }
  }

  console.log('\n==================================================');
  console.log(`TEST SUITE COMPLETE: ${passed} PASSED, ${failed} FAILED`);
  console.log('==================================================\n');

  if (failed > 0) process.exit(1);
}

runAdvisorTests().catch((err) => {
  console.error('Advisor test runner error:', err);
  process.exit(1);
});
