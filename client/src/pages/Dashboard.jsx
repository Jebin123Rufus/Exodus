import { useState } from 'react';
import { getUserRepositories, submitRepositoryMetadata } from '../services/api';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

function Dashboard({ user, onLogout }) {
  const [showRepos, setShowRepos] = useState(false);
  const [repositories, setRepositories] = useState([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [repoError, setRepoError] = useState(null);
  const [selectedRepoId, setSelectedRepoId] = useState(null);
  const [searchFilter, setSearchFilter] = useState('');

  const [submitting, setSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(null);
  const [submitError, setSubmitError] = useState(null);

  const handleSwitchAccount = () => {
    window.location.href = `${API_BASE}/api/auth/switch`;
  };

  const handleListRepositories = async () => {
    setShowRepos(true);
    setSubmitSuccess(null);
    setSubmitError(null);
    if (repositories.length > 0) return;

    setLoadingRepos(true);
    setRepoError(null);
    try {
      const data = await getUserRepositories();
      if (data.repositories) {
        setRepositories(data.repositories);
      }
    } catch (err) {
      console.error('Failed to list repositories:', err);
      setRepoError(err.message || 'Failed to fetch repositories.');
    } finally {
      setLoadingRepos(false);
    }
  };

  const handleSelectRepo = (repoId) => {
    setSelectedRepoId(repoId);
    setSubmitSuccess(null);
    setSubmitError(null);
  };

  const selectedRepo = repositories.find((r) => r.id === selectedRepoId);

  const handleSubmitAnalysis = async () => {
    if (!selectedRepo) return;

    setSubmitting(true);
    setSubmitSuccess(null);
    setSubmitError(null);

    try {
      const result = await submitRepositoryMetadata(selectedRepo);
      setSubmitSuccess(result);
    } catch (err) {
      console.error('Error submitting repository metadata:', err);
      setSubmitError(err.message || 'Failed to submit repository metadata.');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredRepos = repositories.filter((repo) =>
    repo.fullName.toLowerCase().includes(searchFilter.toLowerCase()) ||
    (repo.description && repo.description.toLowerCase().includes(searchFilter.toLowerCase()))
  );

  return (
    <div className="page-container">
      <div className={`card ${showRepos ? 'dashboard-card' : ''}`}>
        <h1>Welcome, {user.displayName || user.username}!</h1>
        <p className="subtitle">You are signed in with GitHub.</p>
        <div className="profile-row">
          {user.avatarUrl && (
            <img className="avatar" src={user.avatarUrl} alt="Avatar" />
          )}
          <div className="user-details">
            <p><strong>GitHub username:</strong> {user.username}</p>
            <p><strong>Email:</strong> {user.email || 'Not available'}</p>
          </div>
        </div>
        <div className="button-group">
          <button
            className="action-button"
            onClick={handleListRepositories}
            disabled={loadingRepos}
          >
            {loadingRepos ? (
              <>
                <span className="spinner"></span> Loading Repositories...
              </>
            ) : (
              'List Repositories'
            )}
          </button>
          <button className="secondary-button" onClick={handleSwitchAccount}>
            Switch Account
          </button>
          <button className="logout-button" onClick={onLogout}>
            Logout
          </button>
        </div>

        {showRepos && (
          <div className="repo-section">
            <h2>
              <span>Your Repositories</span>
              {repositories.length > 0 && (
                <span className="repo-count-badge">{repositories.length} total</span>
              )}
            </h2>

            {repoError && (
              <div className="status-alert error">
                <strong>Error:</strong> {repoError}
              </div>
            )}

            {repositories.length > 0 && (
              <input
                type="text"
                className="repo-search-input"
                placeholder="Search repositories..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
              />
            )}

            {loadingRepos && repositories.length === 0 && (
              <p style={{ color: '#57606a', fontStyle: 'italic' }}>
                Fetching your GitHub repositories...
              </p>
            )}

            {!loadingRepos && repositories.length === 0 && !repoError && (
              <p style={{ color: '#57606a' }}>No repositories found.</p>
            )}

            {filteredRepos.length > 0 && (
              <div className="repo-list">
                {filteredRepos.map((repo) => {
                  const isSelected = repo.id === selectedRepoId;
                  return (
                    <div
                      key={repo.id}
                      className={`repo-item ${isSelected ? 'selected' : ''}`}
                      onClick={() => handleSelectRepo(repo.id)}
                    >
                      <input
                        type="radio"
                        name="selectedRepo"
                        className="repo-radio"
                        checked={isSelected}
                        onChange={() => handleSelectRepo(repo.id)}
                      />
                      <div className="repo-info">
                        <div className="repo-header-row">
                          <span className="repo-name">{repo.fullName}</span>
                          <span
                            className={
                              repo.private ? 'badge-private' : 'badge-public'
                            }
                          >
                            {repo.private ? 'Private' : 'Public'}
                          </span>
                        </div>
                        {repo.description && (
                          <p className="repo-description">{repo.description}</p>
                        )}
                        <div className="repo-meta-row">
                          {repo.language && (
                            <span className="repo-meta-item">
                              <span className="language-dot"></span>
                              {repo.language}
                            </span>
                          )}
                          <span className="repo-meta-item">
                            Branch: <strong>{repo.defaultBranch}</strong>
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {selectedRepo && (
              <div className="submit-container">
                <p className="submit-info-text">
                  Selected Repository: <strong>{selectedRepo.fullName}</strong>
                  <br />
                  Submit metadata (clone URL, default branch, access scopes) to the server for Static Security Analysis.
                </p>
                <button
                  className="submit-button"
                  onClick={handleSubmitAnalysis}
                  disabled={submitting}
                >
                  {submitting ? (
                    <>
                      <span className="spinner"></span> Submitting Metadata...
                    </>
                  ) : (
                    'Submit'
                  )}
                </button>
              </div>
            )}

            {submitSuccess && (
              <div className="status-alert success">
                <strong>✓ Success:</strong> {submitSuccess.message}
                <div style={{ marginTop: '6px', fontSize: '0.8rem', opacity: 0.9 }}>
                  Analysis ID: <code>{submitSuccess.analysisId}</code>
                </div>
              </div>
            )}

            {submitError && (
              <div className="status-alert error">
                <strong>Error:</strong> {submitError}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;