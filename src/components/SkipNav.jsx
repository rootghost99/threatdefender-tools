// Skip navigation link for accessibility
import React from 'react';

export default function SkipNav({ darkMode }) {
  return (
    <a
      href="#main-content"
      className={`sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 px-4 py-2 rounded-md font-semibold transition focus:outline-none focus:ring-2 focus:ring-blue-500 ${
        darkMode
          ? 'bg-gray-800 text-white'
          : 'bg-white text-gray-900 border border-gray-300'
      }`}
    >
      Skip to main content
    </a>
  );
}
