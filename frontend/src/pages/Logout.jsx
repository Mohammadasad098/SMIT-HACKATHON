import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const Logout = () => {
  const [loading, setLoading] = useState(false);
const navigate = useNavigate()


  const Logout = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://localhost:3000/api/v1/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        alert('Logout successful!');
        console.log('User logged out successfully');
        navigate('/login');
      } else {
        alert('Logout failed. Please try again.');
      }
    } catch (error) {
      console.error('Error logging out:', error);
      alert('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={Logout}
      className="py-2 px-4 bg-red-500 text-white rounded hover:bg-red-600"
      disabled={loading}
    >
      {loading ? 'Logging Out...' : 'Logout'}
    </button>
  );
};

export default Logout;
