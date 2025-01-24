import { createRoot } from 'react-dom/client'
import './index.css'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Home from './pages/Home.jsx'
import Login from './pages/Login.jsx'
import Register from './pages/Register.jsx'
import Logout from './pages/Logout.jsx'
import Layout from './Layout.jsx'

const router = createBrowserRouter([
  {
      path: "",
      element: <Layout/>,
      children: [
          {
              path: "",
              element: <Home/>
          },
          {
              path: "register",
              element: <Register/>
          },
          {
              path: "login",
              element: <Login/>
          },
          {
              path: "logout",
              element: <Logout/>
          },
          
      ]
  }
])


createRoot(document.getElementById('root')).render(
  <RouterProvider router={router}>
  </RouterProvider>
)
