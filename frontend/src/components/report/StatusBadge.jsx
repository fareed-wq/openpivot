import React from 'react';

export default function StatusBadge({ status }) {
  let colorClass = 'bg-gray-100 text-gray-800 border-gray-200';
  
  switch (status?.toLowerCase()) {
    case 'success':
      colorClass = 'bg-green-100 text-green-800 border-green-200';
      break;
    case 'partial':
      colorClass = 'bg-yellow-100 text-yellow-800 border-yellow-200';
      break;
    case 'error':
    case 'timeout':
    case 'unavailable':
    case 'blocked':
    case 'not_found':
    case 'rate_limited':
    case 'unsupported':
      colorClass = 'bg-red-100 text-red-800 border-red-200';
      break;
  }

  return (
    <span className={`px-2 py-0.5 rounded border text-xs font-medium uppercase inline-block ${colorClass}`}>
      {status || 'unknown'}
    </span>
  );
}
