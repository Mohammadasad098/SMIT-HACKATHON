import React, { useState, useRef, useEffect } from "react";
import { Link } from 'react-router-dom';

const Navbar = () => {
  const [isOpen, setIsOpen] = useState(false);
  const navbarRef = useRef(null); 

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  const closeMenu = () => {
    setIsOpen(false); 
  };

  const handleLinkClick = () => {
    closeMenu(); 
  };

  const handleCloseClick = (event) => {
    event.stopPropagation();
    closeMenu(); 
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (navbarRef.current && !navbarRef.current.contains(event.target)) {
        closeMenu(); 
      }
    };


    document.addEventListener("mousedown", handleClickOutside);
    
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  return (
    <nav className="border-gray-200 bg-[#00b5fd]">
      <div className="max-w-screen-xl flex flex-wrap items-center justify-between mx-auto p-4">

        {/* Logo */}
        <Link to="/">
          <span className="self-center text-2xl hover:text-white font-semibold whitespace-nowrap text-black">
            Personal Blogging App
          </span>
        </Link>

        {/* Hamburger Menu */}
        <label className="btn-circle bg-[#00b5fd] swap swap-rotate md:hidden">
          <input 
            type="checkbox" 
            checked={isOpen} 
            readOnly
          />
          <svg
            className={`swap-off fill-current ${isOpen ? 'hidden' : ''}`}
            xmlns="http://www.w3.org/2000/svg"
            width="32"
            height="32"
            viewBox="0 0 512 512"
            onClick={toggleMenu}
          >
            <path d="M64,384H448V341.33H64Zm0-106.67H448V234.67H64ZM64,128v42.67H448V128Z" />
          </svg>
          <svg
            className={`swap-on fill-current ${!isOpen ? 'hidden' : ''}`}
            xmlns="http://www.w3.org/2000/svg"
            width="32"
            height="32"
            viewBox="0 0 512 512"
            onClick={handleCloseClick}
          >
            <polygon points="400 145.49 366.51 112 256 222.51 145.49 112 112 145.49 222.51 256 112 366.51 145.49 400 256 289.49 366.51 400 400 366.51 289.49 256 400 145.49" />
          </svg>
        </label>

        {/* Navbar Links */}
        <div
          ref={navbarRef} 
          className={`${isOpen ? "block" : "hidden"} w-full md:block md:w-auto`}
          id="navbar-default"
        >
          <ul className="font-medium flex flex-col p-4 md:p-0 mt-4 border border-gray-100 rounded-lg md:flex-row md:space-x-8 rtl:space-x-reverse md:mt-0 md:border-0">
            {["/" , "/register", "/login", "/logout"].map((path, index) => (
              <li key={index}>
                <Link
                  to={path}
                  className="block py-2 px-3 text-gray-900 rounded hover:bg-gray-100 md:hover:bg-transparent md:border-0 md:hover:text-white md:p-0 dark:text-white dark:hover:text-white md:dark:hover:bg-transparent"
                  onClick={handleLinkClick} 
                >
                  {path === "/" ? "Home" : path.charAt(1).toUpperCase() + path.slice(2)}
                </Link>
              </li>
            ))}
          </ul>
        </div>

      </div>
    </nav>
  );
};

export default Navbar;