const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

function Dashboard({ user, onLogout }) {
  const handleSwitchAccount = () => {
    // Navigate directly to the server-side switch route.
    // It destroys our session and immediately redirects to GitHub's login page
    // so the user can authenticate with any GitHub account.
    window.location.href = `${API_BASE}/api/auth/switch`;
  };

  return (
    <div className="page-container">
      <div className="card">
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
          <button className="secondary-button" onClick={handleSwitchAccount}>
            Switch Account
          </button>
          <button className="logout-button" onClick={onLogout}>
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;