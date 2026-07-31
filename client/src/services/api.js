const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

export async function getCurrentUser() {
  try {
    const res = await fetch(`${API_BASE}/api/auth/user`, {
      credentials: 'include',
    });

    if (!res.ok) {
      return { authenticated: false };
    }

    return await res.json();
  } catch (error) {
    console.error('Failed to get current user:', error);
    return { authenticated: false };
  }
}

export async function logout() {
  const res = await fetch(`${API_BASE}/api/auth/logout`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!res.ok) {
    throw new Error('Logout failed');
  }

  return res.json();
}