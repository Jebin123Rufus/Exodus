import { useEffect, useState } from 'react';
import './App.css';

function App() {
  const [data, setData] = useState('');

  useEffect(() => {
    // Fetch data from the Express backend server
    fetch('http://localhost:5000/api/message')
      .then((res) => res.json())
      .then((data) => setData(data.message))
      .catch((err) => console.error("Error fetching data:", err));
  }, []);

  return (
    <div style={{ textAlign: 'center', marginTop: '50px' }}>
      <h1>React + Express Integration</h1>
      <p>Backend Response: <strong>{data || 'Loading...'}</strong></p>
    </div>
  );
}

export default App;
