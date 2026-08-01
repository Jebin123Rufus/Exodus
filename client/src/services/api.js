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

export async function getUserRepositories() {
  const res = await fetch(`${API_BASE}/api/repos`, {
    credentials: 'include',
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Failed to fetch repositories');
  }

  return res.json();
}

export async function submitRepositoryMetadata(repoMetadata) {
  const res = await fetch(`${API_BASE}/api/repos/submit`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ repoMetadata }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Failed to submit repository metadata');
  }

  return res.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 4: SECURITY REPORT API HELPERS
// ─────────────────────────────────────────────────────────────────────────────

export async function getSecurityReport(analysisId) {
  const res = await fetch(`${API_BASE}/api/report/${analysisId}`, {
    credentials: 'include',
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Failed to fetch security report');
  }

  return res.json();
}

export function downloadReportJsonUrl(analysisId) {
  return `${API_BASE}/api/report/${analysisId}/json`;
}

export function downloadReportMarkdownUrl(analysisId) {
  return `${API_BASE}/api/report/${analysisId}/markdown`;
}