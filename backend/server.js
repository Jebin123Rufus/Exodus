import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { MongoClient, ObjectId } from 'mongodb';

dotenv.config();

const app = express();
const PORT = process.env.PORT;
const FRONTEND_URL = process.env.FRONTEND_URL;
const BASE_URL = process.env.BASE_URL;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;

const client = new MongoClient(MONGODB_URI);

let db;
let users;
let oauthAccounts;

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
          // Also explicitly remove from MongoDB store in case destroy didn't propagate
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

  app.post('/api/repos/submit', async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { repoMetadata } = req.body;
    if (!repoMetadata || !repoMetadata.fullName) {
      return res.status(400).json({ error: 'Invalid repository metadata provided' });
    }

    console.log('Received repository metadata for Static Security Analysis:');
    console.log(JSON.stringify(repoMetadata, null, 2));

    res.json({
      success: true,
      message: `Metadata for repository "${repoMetadata.fullName}" successfully received for Static Security Analysis.`,
      analysisId: `analysis_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      receivedMetadata: {
        ...repoMetadata,
        submittedAt: new Date().toISOString(),
        submittedBy: req.user.username,
      },
    });
  });

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});