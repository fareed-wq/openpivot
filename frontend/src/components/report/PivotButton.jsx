import React from 'react';

export default function PivotButton({ target, onPivot, disabled }) {
  if (!target || !onPivot) return null;

  return (
    <button
      type="button"
      onClick={(e) => {
        e.preventDefault();
        onPivot(target);
      }}
      disabled={disabled}
      className="inline-flex items-center gap-1 px-2 py-0.5 ml-2 bg-blue-50 text-blue-700 hover:bg-blue-100 hover:text-blue-800 disabled:bg-gray-100 disabled:text-gray-400 text-xs font-semibold rounded border border-blue-200 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 cursor-pointer disabled:cursor-not-allowed"
      aria-label={`Pivot investigation to ${target}`}
    >
      <svg xmlns="http://www.w3.org/2000/svg" className="h-3 w-3" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 1.414L10.586 9H7a1 1 0 100 2h3.586l-1.293 1.293a1 1 0 101.414 1.414l3-3a1 1 0 000-1.414z" clipRule="evenodd" />
      </svg>
      Pivot
    </button>
  );
}
