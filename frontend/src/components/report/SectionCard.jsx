import React, { useState, useEffect } from 'react';

export default function SectionCard({ id, title, children, status, collapsible = false, defaultOpen = true, subtitle = null }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  useEffect(() => {
    if (!id || !collapsible) return;
    const handleExpand = () => setIsOpen(true);
    window.addEventListener(`expand-section-${id}`, handleExpand);
    return () => window.removeEventListener(`expand-section-${id}`, handleExpand);
  }, [id, collapsible]);

  return (
    <section id={id} className="bg-white p-6 rounded-xl shadow-sm border border-gray-100 scroll-mt-24">
      <div className={`flex justify-between items-center ${isOpen ? 'mb-4 border-b pb-2' : ''}`}>
        <div className="flex-1">
          <h3 className="text-xl font-bold text-gray-900 capitalize flex items-center gap-2">
            {title}
          </h3>
          {subtitle && !isOpen && (
            <p className="text-sm text-gray-600 mt-1">{subtitle}</p>
          )}
        </div>
        <div className="flex items-center gap-4">
          {status && (
            <div className="text-sm text-gray-500 flex items-center gap-2">
              Status: {status}
            </div>
          )}
          {collapsible && (
            <button
              onClick={() => setIsOpen(!isOpen)}
              aria-expanded={isOpen}
              className="px-2 py-1 bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded text-gray-700 text-sm font-medium flex items-center gap-1 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {isOpen ? (
                <><span>Collapse</span> <span aria-hidden="true">[-]</span></>
              ) : (
                <><span>Expand</span> <span aria-hidden="true">[+]</span></>
              )}
            </button>
          )}
        </div>
      </div>
      {(!collapsible || isOpen) && (
        <div>
          {children}
        </div>
      )}
    </section>
  );
}
