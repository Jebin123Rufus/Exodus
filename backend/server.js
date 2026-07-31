import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { MongoClient, ObjectId } from 'mongodb';
import Groq from 'groq-sdk';
import ignore from 'ignore';
import { SemanticChunkingService } from './src/chunking/semanticChunkingService.js';
import { EvidenceExtractionService } from './src/evidence/evidenceExtractionService.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL;
const BASE_URL = process.env.BASE_URL;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Initialize Groq SDK
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY
});

const client = new MongoClient(MONGODB_URI);

let db;
let users;
let oauthAccounts;
let analysisResults; // Collection to store the extracted files output
let semanticChunks; // Collection to store generated semantic chunks
let securityEvidence; // Collection to store Phase 2 Security Evidence Graph documents

// In-Memory storage on the server for quick access to extracted files
const extractedFilesStore = new Map();

passport.serializeUser((user, done) => {
  done(null, user._id.toString());
});

passport.deserializeUser(async (id, done) => {
  try {
    if (!ObjectId.isValid(id)) {
      return done(null, null);
    }
    const user = await users.findOne({ _id: new ObjectId(id) });
    done(null, user || null);
  } catch (err) {
    done(err);
  }
});

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${BASE_URL}/api/auth/github/callback`,
      scope: ['user:email', 'repo'],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const githubId = profile.id;
        const email =
          profile.emails && profile.emails.length
            ? profile.emails[0].value
            : null;

        const userData = {
          githubId,
          username: profile.username,
          displayName: profile.displayName || profile.username,
          email,
          avatarUrl: profile._json?.avatar_url,
          updatedAt: new Date(),
        };

        const upsertResult = await users.findOneAndUpdate(
          { githubId },
          { $set: userData, $setOnInsert: { createdAt: new Date() } },
          { upsert: true, returnDocument: 'after' }
        );

        let user = upsertResult?.value || upsertResult;
        if (!user || !user._id) {
          user = await users.findOne({ githubId });
        }

        if (!user) {
          return done(new Error('Failed to create or load user'));
        }

        await oauthAccounts.updateOne(
          { provider: 'github', providerId: githubId },
          {
            $set: {
              provider: 'github',
              providerId: githubId,
              userId: user._id,
              accessToken,
              profile,
              updatedAt: new Date(),
            },
            $setOnInsert: { createdAt: new Date() },
          },
          { upsert: true }
        );

        done(null, user);
      } catch (error) {
        done(error);
      }
    }
  )
);

async function startServer() {
  await client.connect();
  db = client.db('exodus');
  users = db.collection('users');
  oauthAccounts = db.collection('oauthAccounts');
  analysisResults = db.collection('analysisResults');
  semanticChunks = db.collection('semantic_chunks');
  securityEvidence = db.collection('security_evidence');

  try {
    await semanticChunks.createIndex({ analysisId: 1, filePath: 1, chunkIndex: 1 }, { unique: true });
    await semanticChunks.createIndex({ chunkId: 1 }, { unique: true });
  } catch (idxErr) {
    console.warn('Notice while setting up semantic_chunks collection indexes:', idxErr.message);
  }

  try {
    await securityEvidence.createIndex({ analysisId: 1, chunkId: 1 }, { unique: true });
    await securityEvidence.createIndex({ analysisId: 1, filePath: 1 });
  } catch (idxErr) {
    console.warn('Notice while setting up security_evidence collection indexes:', idxErr.message);
  }

  app.use(
    cors({
      origin: FRONTEND_URL,
      credentials: true,
    })
  );
  app.use(express.json());

  app.use(
    session({
      secret: SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        client: client,
        dbName: 'exodus',
        collectionName: 'sessions',
        touchAfter: 24 * 3600,
      }),
      cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000,
      },
    })
  );

  app.use(passport.initialize());
  app.use(passport.session());

  app.get(
    '/api/auth/github',
    (req, res, next) => {
      req.session.regenerate((err) => {
        if (err) return next(err);
        next();
      });
    },
    passport.authenticate('github', { session: true })
  );

  app.get(
    '/api/auth/github/callback',
    passport.authenticate('github', {
      failureRedirect: `${FRONTEND_URL}/?auth=failed`,
      session: true,
    }),
    (req, res) => {
      req.session.regenerate((err) => {
        if (err) {
          console.error('Session regeneration error after GitHub callback:', err);
        }
        req.session.passport = { user: req.user._id.toString() };
        req.session.save((saveErr) => {
          if (saveErr) console.error('Session save error after regeneration:', saveErr);
          res.redirect(`${FRONTEND_URL}/dashboard`);
        });
      });
    }
  );

  app.get('/api/auth/switch', (req, res, next) => {
    const sessionId = req.session?.id;

    const startOAuth = () => {
      const githubOAuthURL =
        `https://github.com/login/oauth/authorize` +
        `?client_id=${process.env.GITHUB_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(`${BASE_URL}/api/auth/github/callback`)}` +
        `&scope=user%3Aemail%20repo` +
        `&login=` +
        `&prompt=select_account`;
      res.redirect(githubOAuthURL);
    };

    if (!req.session) {
      return startOAuth();
    }

    req.logout((err) => {
      if (err) console.error('Switch-account logout error:', err);
      req.session.destroy(async () => {
        if (sessionId) {
          try {
            await db.collection('sessions').deleteOne({ _id: sessionId });
          } catch (e) {
            console.error('Failed to delete session from DB during switch:', e);
          }
        }
        res.clearCookie('connect.sid', { path: '/' });
        startOAuth();
      });
    });
  });

  app.get('/api/auth/user', (req, res) => {
    if (!req.user) {
      return res.status(401).json({ authenticated: false });
    }
    const { _id, githubId, username, displayName, email, avatarUrl } = req.user;
    res.json({
      authenticated: true,
      user: { id: _id.toString(), githubId, username, displayName, email, avatarUrl },
    });
  });

  app.post('/api/auth/logout', (req, res, next) => {
    const sessionId = req.session?.id;

    req.logout((err) => {
      if (err) return next(err);

      const finish = () => {
        res.clearCookie('connect.sid', { path: '/' });
        return res.json({ success: true });
      };

      if (req.session) {
        req.session.destroy(async (err) => {
          if (err) console.error('Session destroy error:', err);
          if (sessionId) {
            try {
              await db.collection('sessions').deleteOne({ _id: sessionId });
            } catch (e) {
              console.error('Failed to delete session from DB:', e);
            }
          }
          finish();
        });
      } else {
        finish();
      }
    });
  });

  app.get('/api/message', (req, res) => {
    res.json({ message: 'Hello from the Express backend!' });
  });

  app.get('/api/repos', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
      const oauthAcc = await oauthAccounts.findOne({
        userId: req.user._id,
        provider: 'github',
      });

      if (!oauthAcc || !oauthAcc.accessToken) {
        return res.status(400).json({ error: 'No GitHub access token found for user' });
      }

      const ghResponse = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&type=all', {
        headers: {
          Authorization: `Bearer ${oauthAcc.accessToken}`,
          'User-Agent': 'Exodus-App',
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (!ghResponse.ok) {
        const errorText = await ghResponse.text();
        console.error('GitHub API error:', ghResponse.status, errorText);
        return res.status(ghResponse.status).json({ error: 'Failed to fetch repositories from GitHub' });
      }

      const repos = await ghResponse.json();

      const formattedRepos = repos.map((repo) => ({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        owner: {
          login: repo.owner?.login,
          avatarUrl: repo.owner?.avatar_url,
          type: repo.owner?.type,
        },
        private: repo.private,
        htmlUrl: repo.html_url,
        cloneUrl: repo.clone_url,
        sshUrl: repo.ssh_url,
        defaultBranch: repo.default_branch,
        language: repo.language || 'Unknown',
        description: repo.description,
        updatedAt: repo.updated_at,
        stargazersCount: repo.stargazers_count,
        forksCount: repo.forks_count,
      }));

      res.json({ success: true, repositories: formattedRepos });
    } catch (err) {
      console.error('Error fetching user repositories:', err);
      res.status(500).json({ error: 'Internal server error while fetching repositories' });
    }
  });

  // SUBMIT ENDPOINT: Extracts file names -> Excludes ONLY items defined in .gitignore
  app.post('/api/repos/submit', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { repoMetadata } = req.body;
    if (!repoMetadata || !repoMetadata.fullName) {
      return res.status(400).json({ error: 'Invalid repository metadata provided' });
    }

    try {
      const oauthAcc = await oauthAccounts.findOne({
        userId: req.user._id,
        provider: 'github',
      });

      if (!oauthAcc || !oauthAcc.accessToken) {
        return res.status(400).json({ error: 'No GitHub access token found for user' });
      }

      const defaultBranch = repoMetadata.defaultBranch || 'main';
      const [owner, repoName] = repoMetadata.fullName.split('/');

      // 1. Fetch full file tree recursively from GitHub Trees API
      const treeUrl = `https://api.github.com/repos/${owner}/${repoName}/git/trees/${defaultBranch}?recursive=1`;
      const treeResponse = await fetch(treeUrl, {
        headers: {
          Authorization: `Bearer ${oauthAcc.accessToken}`,
          'User-Agent': 'Exodus-App',
          Accept: 'application/vnd.github.v3+json',
        },
      });

      if (!treeResponse.ok) {
        const errText = await treeResponse.text();
        console.error('GitHub Trees API error:', treeResponse.status, errText);
        return res.status(treeResponse.status).json({ error: 'Failed to retrieve repository file structure from GitHub.' });
      }

      const treeData = await treeResponse.json();
      const rawTreeItems = treeData.tree || [];

      // Filter to retain ONLY files (type: 'blob') and strip directory items (type: 'tree')
      const allFilePaths = rawTreeItems
        .filter((item) => item.type === 'blob')
        .map((item) => item.path);

      console.log(`[Total Files Received]: ${allFilePaths.length} file paths from GitHub API.`);

      // 2. Load .gitignore rules from repository if present
      const gitignoreParser = ignore();
      try {
        const gitignoreUrl = `https://raw.githubusercontent.com/${owner}/${repoName}/${defaultBranch}/.gitignore`;
        const gitignoreResponse = await fetch(gitignoreUrl, {
          headers: { Authorization: `Bearer ${oauthAcc.accessToken}` },
        });

        if (gitignoreResponse.ok) {
          const gitignoreContent = await gitignoreResponse.text();
          gitignoreParser.add(gitignoreContent);
          console.log('Successfully loaded .gitignore rules from repository.');
        }
      } catch (gitignoreErr) {
        console.warn('No .gitignore found or failed to fetch .gitignore:', gitignoreErr.message);
      }

      // 3. Add default ignores (node_modules, .git, build, dist, vendor) + repository .gitignore rules
      gitignoreParser.add([
        'node_modules', 'node_modules/', 'node_modules/**',
        '.git', '.git/', '.git/**',
        'dist', 'dist/', 'dist/**',
        'build', 'build/', 'build/**',
        'vendor', 'vendor/', 'vendor/**',
        '.venv', 'venv', '.next', '.nuxt', 'coverage'
      ]);

      // Filter full relative file paths against gitignore rules
      const nonIgnoredPaths = allFilePaths.filter((pathStr) => !gitignoreParser.ignores(pathStr));

      // 4. Convert non-ignored paths to JUST standalone file names & deduplicate (and omit .gitignore itself)
      const fileNamesList = [...new Set(nonIgnoredPaths.map((pathStr) => pathStr.split('/').pop()))]
        .filter((name) => name.toLowerCase() !== '.gitignore' && name.toLowerCase() !== '.gitkeep');

      console.log(`[Filtered File Names]: Reduced from ${rawTreeItems.length} total tree items to ${fileNamesList.length} unique non-ignored file names.`);

      // 5. System Prompt instructing the LLM to extract key file names
      const systemPrompt = `You are a language-agnostic software security, testing, and codebase analyzer.

YOUR TASK:
Analyze a list of file names from a software repository and extract ALL essential file names that could be relevant for application structure, business logic, code development, testing, configuration, or security vulnerability analysis.

LANGUAGE & FRAMEWORK AGNOSTIC:
Must work for any language, framework, runtime, or project structure (JavaScript, TypeScript, Python, Java, Go, Rust, C/C++, C#, PHP, Ruby, Kotlin, Swift, Dart, Shell, etc.).

WHAT TO INCLUDE (KEEP ALL OF THESE):
1. Code & Templates:
   - ALL source code files, components, scripts, utility modules, and handlers.
   - ALL structure, markups, and template files (e.g., .html, .htm, .jsx, .tsx, .vue, .svelte, .php, .erb, etc.). DO NOT exclude HTML or web structure files!
2. Dependency & Configuration Manifests:
   - Primary package/dependency declaration files (e.g., package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml, pom.xml, build.gradle, Dockerfile, Makefile).
3. Text & Config Files (POTENTIAL CREDENTIALS / CONFIGS):
   - ALL .txt, .env, .config, .json, .yaml, .yml, .xml, .ini, .properties files (these often contain sensitive credentials, secrets, or system parameters for security testing).
4. Database & Schemas:
   - Database migrations, ORM schemas, and query scripts (e.g., .sql, .prisma).

WHAT TO EXCLUDE (OMIT ALL OF THESE):
1. Version Control & VCS Dotfiles:
   - ALL .gitignore, .gitkeep, .gitattributes, .gitlab-ci.yml, and related VCS meta files.
2. Static Media & Binary Assets:
   - Images, vector graphics, audio, video, font files (e.g., .png, .jpg, .jpeg, .gif, .svg, .ico, .webp, .ttf, .woff, .woff2, .mp3, .mp4, .pdf).
3. Pure Presentation Stylesheets:
   - Standalone styling assets (e.g., .css, .scss, .sass, .less).
4. Secondary Lockfiles & Minified Output:
   - Dependency lockfiles (e.g., package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, poetry.lock, Gemfile.lock).
   - Minified outputs and sourcemaps (*.min.js, *.min.css, *.map).
5. System & IDE Metadata:
   - OS metadata and cache (.DS_Store, Thumbs.db).

RULE: If a file could contain logic, markup, configuration, credentials, or testable code, YOU MUST INCLUDE IT. DO NOT include .gitignore or static assets.

OUTPUT FORMAT REQUIREMENT:
- Output MUST be a single valid JSON object containing a "files" key with an array of string file names.
- Example: { "files": ["index.html", "server.js", "config.txt", "package.json"] }`;

      // 6. Execute Groq API Request (chunking if fileNamesList is large to respect Groq token limits)
      const MAX_BATCH_SIZE = 400; // Keep message payload safely within Groq 12,000 TPM rate limits
      let extractedFiles = [];

      for (let i = 0; i < fileNamesList.length; i += MAX_BATCH_SIZE) {
        const batch = fileNamesList.slice(i, i + MAX_BATCH_SIZE);
        const completion = await groq.chat.completions.create({
          messages: [
            { role: 'system', content: systemPrompt },
            {
              role: 'user',
              content: `Extract essential file names from this list:\n${JSON.stringify(batch)}`,
            },
          ],
          model: 'llama-3.3-70b-versatile',
          temperature: 0.1,
          max_completion_tokens: 4096,
          response_format: { type: 'json_object' },
        });

        const rawResponse = completion.choices[0]?.message?.content || '{}';
        try {
          const parsed = JSON.parse(rawResponse);
          let batchExtracted = [];
          if (Array.isArray(parsed)) {
            batchExtracted = parsed;
          } else if (Array.isArray(parsed.files)) {
            batchExtracted = parsed.files;
          } else {
            const possibleArray = Object.values(parsed).find(val => Array.isArray(val));
            batchExtracted = possibleArray || [];
          }
          extractedFiles.push(...batchExtracted);
        } catch (parseError) {
          console.error('Failed to parse JSON response chunk from LLM:', parseError);
        }
      }

      // Deduplicate final extracted list & resolve to full relative repo paths
      extractedFiles = [...new Set(extractedFiles)].map((fileName) => {
        const matchingPath = nonIgnoredPaths.find((p) => p.endsWith(`/${fileName}`) || p === fileName);
        return matchingPath || fileName;
      });

      // 7. Log output
      console.log('\n================================================================================');
      console.log(`[EXTRACTED CORE FILES FOR]: ${repoMetadata.fullName}`);
      console.log(`[TOTAL EXTRACTED FILES]:    ${extractedFiles.length}`);
      console.log('================================================================================');
      console.log(JSON.stringify(extractedFiles, null, 2));
      console.log('================================================================================\n');

      const analysisId = `analysis_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

      // 8. Store Record in Server Memory & Upsert in MongoDB under user & repository
      const analysisRecord = {
        analysisId,
        userId: req.user._id,
        username: req.user.username,
        repoFullName: repoMetadata.fullName,
        repoId: repoMetadata.id,
        repoMetadata,
        totalPathsReceived: rawTreeItems.length,
        fileNamesPassedToModel: fileNamesList.length,
        extractedFilesCount: extractedFiles.length,
        extractedFiles,
        chunkingStatus: 'PENDING',
        updatedAt: new Date(),
      };

      extractedFilesStore.set(analysisId, analysisRecord);

      await analysisResults.updateOne(
        { userId: req.user._id, repoFullName: repoMetadata.fullName },
        {
          $set: analysisRecord,
          $setOnInsert: { createdAt: new Date() }
        },
        { upsert: true }
      );

      // 9. AUTOMATICALLY TRIGGER SEMANTIC CHUNKING SERVICE IMMEDIATELY AS FILES ARE ADDED
      console.log(`🚀 [AUTOMATIC CHUNKING TRIGGERED] Starting Semantic Chunking Pipeline for ${repoMetadata.fullName}...`);
      SemanticChunkingService.processAnalysis(db, analysisId, {
        accessToken: oauthAcc.accessToken,
        owner,
        repoName,
        defaultBranch
      }).catch((chunkErr) => {
        console.error(`❌ [Background Semantic Chunking Error] Pipeline failed for ${analysisId}:`, chunkErr);
      });

      res.json({
        success: true,
        message: `Filtered repository down to ${fileNamesList.length} non-ignored unique file names and extracted ${extractedFiles.length} key file names. Saved to repository record in database.`,
        analysisId,
        totalPathsReceived: rawTreeItems.length,
        fileNamesPassedToModel: fileNamesList.length,
        extractedFilesCount: extractedFiles.length,
        extractedFiles,
      });
    } catch (err) {
      console.error('Error during repository file extraction pipeline:', err);
      res.status(500).json({ error: 'Internal server error while processing repository files.' });
    }
  });

  // GET ENDPOINT: Retrieve stored analysis by ID or by repository full name
  app.get('/api/analysis/:analysisId', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { analysisId } = req.params;

    if (extractedFilesStore.has(analysisId)) {
      console.log(`[Store Match]: Found ${analysisId} in server memory.`);
      return res.json({ success: true, source: 'memory', analysis: extractedFilesStore.get(analysisId) });
    }

    try {
      const record = await analysisResults.findOne({ analysisId });
      if (!record) {
        return res.status(404).json({ error: 'Analysis record not found' });
      }
      res.json({ success: true, source: 'database', analysis: record });
    } catch (err) {
      console.error('Error fetching analysis record:', err);
      res.status(500).json({ error: 'Failed to retrieve analysis record' });
    }
  });

  // GET ENDPOINT: Retrieve extracted files by repoFullName
  app.get('/api/repos/analysis', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { repoFullName } = req.query;
    if (!repoFullName) {
      return res.status(400).json({ error: 'repoFullName query parameter is required' });
    }

    try {
      const record = await analysisResults.findOne({
        userId: req.user._id,
        repoFullName,
      });

      if (!record) {
        return res.status(404).json({ error: 'No analysis found for this repository' });
      }

      res.json({ success: true, analysis: record });
    } catch (err) {
      console.error('Error fetching repository analysis:', err);
      res.status(500).json({ error: 'Failed to retrieve repository analysis record' });
    }
  });

  // POST ENDPOINT: Trigger backend-only Semantic Chunking pipeline for an analysis ID
  app.post('/api/chunking/process/:analysisId', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { analysisId } = req.params;
    const { options } = req.body || {};

    try {
      const record = await analysisResults.findOne({ analysisId });
      if (!record) {
        return res.status(404).json({ error: 'Analysis record not found' });
      }

      // Trigger background semantic chunking process asynchronously
      SemanticChunkingService.processAnalysis(db, analysisId, options).catch((err) => {
        console.error(`[Background Chunking Error] Pipeline failed for ${analysisId}:`, err);
      });

      res.json({
        success: true,
        message: `Semantic chunking pipeline triggered for analysis ${analysisId}`,
        analysisId,
        status: 'IN_PROGRESS'
      });
    } catch (err) {
      console.error('Error triggering semantic chunking pipeline:', err);
      res.status(500).json({ error: 'Failed to trigger semantic chunking pipeline' });
    }
  });

  // GET ENDPOINT: Retrieve live chunking status & progress for an analysis
  app.get('/api/chunking/status/:analysisId', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { analysisId } = req.params;

    try {
      const record = await analysisResults.findOne({ analysisId });
      if (!record) {
        return res.status(404).json({ error: 'Analysis record not found' });
      }

      res.json({
        success: true,
        analysisId,
        chunkingStatus: record.chunkingStatus || 'NOT_STARTED',
        totalFilesToChunk: record.totalFilesToChunk || record.extractedFilesCount || 0,
        processedFiles: record.processedFiles || 0,
        completedFiles: record.completedFiles || 0,
        failedFiles: record.failedFiles || 0,
        totalChunks: record.totalChunks || 0,
        lastChunkedAt: record.lastChunkedAt || null,
        fileProgress: record.fileProgress || {}
      });
    } catch (err) {
      console.error('Error fetching chunking status:', err);
      res.status(500).json({ error: 'Failed to retrieve chunking status' });
    }
  });

  // GET ENDPOINT: Fetch generated semantic chunks from semantic_chunks collection
  app.get('/api/chunking/chunks/:analysisId', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { analysisId } = req.params;
    const { filePath, limit = 100, skip = 0 } = req.query;

    try {
      const filter = { analysisId };
      if (filePath) {
        filter.filePath = filePath;
      }

      const parsedLimit = Math.min(500, parseInt(limit, 10) || 100);
      const parsedSkip = Math.max(0, parseInt(skip, 10) || 0);

      const chunks = await semanticChunks
        .find(filter)
        .sort({ filePath: 1, chunkIndex: 1 })
        .skip(parsedSkip)
        .limit(parsedLimit)
        .toArray();

      const totalCount = await semanticChunks.countDocuments(filter);

      res.json({
        success: true,
        analysisId,
        totalChunks: totalCount,
        count: chunks.length,
        skip: parsedSkip,
        limit: parsedLimit,
        chunks
      });
    } catch (err) {
      console.error('Error fetching semantic chunks:', err);
      res.status(500).json({ error: 'Failed to retrieve semantic chunks' });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────
  // PHASE 2: SENTINELAI SECURITY EVIDENCE EXTRACTION ENGINE ENDPOINTS
  // ─────────────────────────────────────────────────────────────────────────

  // POST ENDPOINT: Manually trigger Phase 2 evidence extraction for an analysisId
  app.post('/api/evidence/process/:analysisId', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

    const { analysisId } = req.params;

    try {
      const record = await analysisResults.findOne({ analysisId });
      if (!record) return res.status(404).json({ error: 'Analysis record not found' });

      const chunkCount = await semanticChunks.countDocuments({ analysisId });
      if (chunkCount === 0) {
        return res.status(400).json({ error: 'No semantic chunks found for this analysis. Run chunking first.' });
      }

      // Trigger Phase 2 in background
      EvidenceExtractionService.processAnalysisEvidence(db, analysisId).catch((err) => {
        console.error(`❌ [Phase 2 Manual Trigger Error] ${analysisId}:`, err.message);
      });

      res.json({
        success: true,
        message: `SentinelAI Phase 2 evidence extraction triggered for ${analysisId}`,
        analysisId,
        chunksQueued: chunkCount,
        phase2Status: 'IN_PROGRESS'
      });
    } catch (err) {
      console.error('Error triggering Phase 2 evidence extraction:', err);
      res.status(500).json({ error: 'Failed to trigger Phase 2 evidence extraction' });
    }
  });

  // GET ENDPOINT: Live Phase 2 evidence extraction status & node/edge counts
  app.get('/api/evidence/status/:analysisId', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

    const { analysisId } = req.params;

    try {
      const record = await analysisResults.findOne({ analysisId });
      if (!record) return res.status(404).json({ error: 'Analysis record not found' });

      const totalChunks = await semanticChunks.countDocuments({ analysisId });
      const completedChunks = await semanticChunks.countDocuments({ analysisId, evidenceExtracted: true });
      const failedChunks = await semanticChunks.countDocuments({ analysisId, status: 'FAILED' });
      const totalEvidenceDocs = await securityEvidence.countDocuments({ analysisId });

      res.json({
        success: true,
        analysisId,
        phase2Status: record.phase2Status || 'NOT_STARTED',
        totalChunks,
        completedChunks,
        failedChunks,
        totalEvidenceDocuments: totalEvidenceDocs,
        extractedNodesCount: record.extractedEvidenceCount || 0,
        extractedEdgesCount: record.extractedEdgesCount || 0,
        frameworks: record.evidenceGraph?.frameworks || [],
        lastPhase2StartedAt: record.lastPhase2StartedAt || null,
        lastPhase2CompletedAt: record.lastPhase2CompletedAt || null
      });
    } catch (err) {
      console.error('Error fetching Phase 2 status:', err);
      res.status(500).json({ error: 'Failed to retrieve Phase 2 evidence status' });
    }
  });

  // GET ENDPOINT: Return full aggregated Security Evidence Graph (nodes + edges)
  app.get('/api/evidence/graph/:analysisId', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

    const { analysisId } = req.params;
    const { filePath, nodeType, limit = 200, skip = 0 } = req.query;

    try {
      const record = await analysisResults.findOne({ analysisId });
      if (!record) return res.status(404).json({ error: 'Analysis record not found' });

      // Build evidence query filter for per-chunk evidence docs
      const filter = { analysisId };
      if (filePath) filter.filePath = filePath;

      const parsedLimit = Math.min(500, parseInt(limit, 10) || 200);
      const parsedSkip = Math.max(0, parseInt(skip, 10) || 0);

      const evidenceDocs = await securityEvidence
        .find(filter, { projection: { nodes: 1, edges: 1, filePath: 1, language: 1, frameworks: 1, chunkId: 1, chunkIndex: 1 } })
        .sort({ filePath: 1, chunkIndex: 1 })
        .skip(parsedSkip)
        .limit(parsedLimit)
        .toArray();

      // Flatten nodes and edges from evidence docs, optionally filter by nodeType
      let allNodes = [];
      let allEdges = [];

      for (const doc of evidenceDocs) {
        let docNodes = Array.isArray(doc.nodes) ? doc.nodes : [];
        if (nodeType) {
          docNodes = docNodes.filter((n) => n.type === nodeType.toUpperCase());
        }
        allNodes.push(...docNodes);
        allEdges.push(...(Array.isArray(doc.edges) ? doc.edges : []));
      }

      res.json({
        success: true,
        analysisId,
        phase2Status: record.phase2Status || 'NOT_STARTED',
        frameworks: record.evidenceGraph?.frameworks || [],
        totalNodesReturned: allNodes.length,
        totalEdgesReturned: allEdges.length,
        skip: parsedSkip,
        limit: parsedLimit,
        nodes: allNodes,
        edges: allEdges
      });
    } catch (err) {
      console.error('Error fetching Security Evidence Graph:', err);
      res.status(500).json({ error: 'Failed to retrieve Security Evidence Graph' });
    }
  });

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});