// Breadcrumb navigation component
import React from 'react';
import { Link } from 'react-router-dom';

export default function Breadcrumb({ items, darkMode }) {
  if (!items || items.length === 0) return null;

  const textColor = darkMode ? 'text-gray-400' : 'text-gray-600';
  const linkColor = darkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-700';
  const separatorColor = darkMode ? 'text-gray-600' : 'text-gray-400';

  return (
    <nav aria-label="Breadcrumb" className={`flex items-center space-x-2 text-sm mb-4 ${textColor}`}>
      {items.map((item, index) => {
        const isLast = index === items.length - 1;

        return (
          <React.Fragment key={item.label}>
            {index > 0 && (
              <span className={separatorColor} aria-hidden="true">
                /
              </span>
            )}
            {isLast ? (
              <span className={`font-medium ${darkMode ? 'text-white' : 'text-gray-900'}`} aria-current="page">
                {item.label}
              </span>
            ) : (
              <Link
                to={item.href}
                className={`${linkColor} transition-colors`}
              >
                {item.label}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}
