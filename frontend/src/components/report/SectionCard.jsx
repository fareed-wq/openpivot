import React from 'react';

export default function SectionCard({ title, children, status }) {
  return (
    <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
      <div className="flex justify-between items-center mb-4 border-b pb-2">
        <h3 className="text-xl font-bold text-gray-900 capitalize">{title}</h3>
        {status && (
          <div className="text-sm text-gray-500 flex items-center gap-2">
            Status: {status}
          </div>
        )}
      </div>
      <div>
        {children}
      </div>
    </section>
  );
}
