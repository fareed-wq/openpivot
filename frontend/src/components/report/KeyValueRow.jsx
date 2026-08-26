import React from 'react';

export default function KeyValueRow({ label, value, className = "" }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className={`py-1 ${className}`}>
      <span className="font-semibold text-gray-700 mr-2">{label}:</span>
      <span className="text-gray-900 break-words">{value}</span>
    </div>
  );
}
