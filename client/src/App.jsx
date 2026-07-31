import { useEffect, useState } from 'react';
import { getCurrentUser, logout } from './services/api';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import './App.css';
import './pages/LoginPage.css';

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadUser() {
      try {
        const data = await getCurrentUser();
        if (data.authenticated) {
          setUser(data.user);
          if (window.location.pathname !== '/dashboard') {
            window.history.replaceState({}, '', '/dashboard');
          }
        } else {
          setUser(null);
          if (window.location.pathname === '/dashboard') {
            window.history.replaceState({}, '', '/');
          }
        }
      } catch (error) {
        console.error('Failed to load user:', error);
        setUser(null);
        if (window.location.pathname === '/dashboard') {
          window.history.replaceState({}, '', '/');
        }
      } finally {
        setLoading(false);
      }
    }

    loadUser();
  }, []);

  const handleLogout = async () => {
    try {
      await logout();
      window.location.replace('/');
    } catch (error) {
      console.error('Logout failed:', error);
      window.location.replace('/');
    }
  };

  if (loading) {
    return (
      <div className="page-container">
        <div className="card">
          <p>Loading…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      {user ? (
        <Dashboard user={user} onLogout={handleLogout} />
      ) : (
        <LoginPage />
      )}
    </div>
  );
}

export default App;