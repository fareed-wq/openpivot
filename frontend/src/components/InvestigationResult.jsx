import React from 'react';

const getStatusColor = (status) => {
  switch (status) {
    case 'success':
      return 'bg-green-100 text-green-800 border-green-200';
    case 'partial':
      return 'bg-yellow-100 text-yellow-800 border-yellow-200';
    case 'error':
    case 'timeout':
    case 'unavailable':
      return 'bg-red-100 text-red-800 border-red-200';
    default:
      return 'bg-gray-100 text-gray-800 border-gray-200';
  }
};

export default function InvestigationResult({ result }) {
  if (!result) return null;

  const { target, status, investigation_id, duration_ms, started_at, completed_at, collector_status, collectors, correlation } = result;

  return (
    <div className="w-full text-left space-y-6 mt-8">
      {/* Overview Section */}
      <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 className="text-xl font-bold text-gray-900 mb-4 border-b pb-2">Investigation Overview</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-700">
          <div><span className="font-semibold">Target:</span> {target?.normalized}</div>
          <div><span className="font-semibold">Type:</span> {target?.type}</div>
          <div>
            <span className="font-semibold">Overall Status: </span> 
            <span className={`px-2 py-0.5 rounded border text-xs font-medium uppercase ${getStatusColor(status)}`}>
              {status}
            </span>
          </div>
          <div><span className="font-semibold">Investigation ID:</span> {investigation_id}</div>
          <div><span className="font-semibold">Started At:</span> {new Date(started_at).toLocaleString()}</div>
          <div><span className="font-semibold">Completed At:</span> {new Date(completed_at).toLocaleString()}</div>
          <div><span className="font-semibold">Duration:</span> {Math.round(duration_ms)} ms</div>
        </div>
      </section>

      {/* Collector Statuses */}
      <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 className="text-xl font-bold text-gray-900 mb-4 border-b pb-2">Data Source Status</h3>
        <div className="flex flex-wrap gap-3">
          {collector_status && Object.entries(collector_status).map(([name, colStatus]) => (
            <div key={name} className={`px-3 py-1.5 rounded-full border text-sm font-medium flex items-center gap-2 ${getStatusColor(colStatus)}`}>
              <span className="capitalize">{name.replace(/_/g, ' ')}</span>
              <span className="opacity-75 text-xs uppercase">{colStatus}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Raw Collectors */}
      {collectors && Object.entries(collectors).map(([name, data]) => (
        <section key={name} className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-xl font-bold text-gray-900 mb-4 border-b pb-2 capitalize">{name.replace(/_/g, ' ')} Output</h3>
          <pre className="bg-gray-50 p-4 rounded-lg text-xs overflow-x-auto border border-gray-200">
            {JSON.stringify(data, null, 2)}
          </pre>
        </section>
      ))}

      {/* Correlation Section */}
      {correlation && (
        <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
          <h3 className="text-xl font-bold text-gray-900 mb-4 border-b pb-2">Correlation</h3>
          <div className="text-sm text-gray-700 mb-4">
            <span className="font-semibold mr-4">Entities: {correlation.entities?.length || 0}</span>
            <span className="font-semibold">Relationships: {correlation.relationships?.length || 0}</span>
          </div>
          
          {correlation.entities?.length > 0 && (
            <div className="mb-6">
              <h4 className="font-bold text-gray-800 mb-2">Entities</h4>
              <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
                {correlation.entities.map((e, idx) => (
                  <li key={idx}><span className="font-semibold">{e.type}:</span> {e.value}</li>
                ))}
              </ul>
            </div>
          )}

          {correlation.relationships?.length > 0 && (
            <div>
              <h4 className="font-bold text-gray-800 mb-2">Relationships</h4>
              <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
                {correlation.relationships.map((r, idx) => (
                  <li key={idx}>
                    {r.source} <span className="font-semibold text-blue-600 px-1">→ {r.type} →</span> {r.target}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
