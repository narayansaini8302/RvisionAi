// src/App.jsx
import { RouterProvider } from 'react-router'
import { router } from './app.routes'
import { AuthProvider } from './features/auth/auth.context'
import { InterviewProvider } from './features/interviewai/interview.context'
import { useEffect } from 'react'

function App() {
  useEffect(() => {
    // Disable right-click globally
    const disableRightClick = (e) => {
      e.preventDefault();
      return false;
    };

    document.addEventListener('contextmenu', disableRightClick);
    
    return () => {
      document.removeEventListener('contextmenu', disableRightClick);
    };
  }, []);

  return (
    <AuthProvider>
      <InterviewProvider>
        <RouterProvider router={router} />
      </InterviewProvider>
    </AuthProvider>
  )
}

export default App