function Dashboard({ user, onLogout }) {
  return (
    <div className="page-container">
      <div className="card">
        <h1>Welcome, {user.displayName || user.username}!</h1>
        <p>You are signed in with GitHub.</p>
        <div className="profile-row">
          {user.avatarUrl && (
            <img className="avatar" src={user.avatarUrl} alt="Avatar" />
          )}
          <div>
            <p><strong>GitHub username:</strong> {user.username}</p>
            <p><strong>Email:</strong> {user.email || 'Not available'}</p>
          </div>
        </div>
        <button className="secondary-button" onClick={onLogout}>
          Logout
        </button>
      </div>
    </div>
  );
}

export default Dashboard;