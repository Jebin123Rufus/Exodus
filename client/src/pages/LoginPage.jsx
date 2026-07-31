import './LoginPage.css';

const API_BASE = 'http://localhost:8000';

function LoginPage() {
  const handleLogin = () => {
    window.location.href = `${API_BASE}/api/auth/github`;
  };

  return (
    <div className="page-container">
      <div className="card">
        <h1>EXODUS</h1>
        <p>Login with GitHub to access your dashboard.</p>
        <button className="primary-button" onClick={handleLogin}>
          Login with GitHub
        </button>
      </div>
    </div>
  );
}

export default LoginPage;