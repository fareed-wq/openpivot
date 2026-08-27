import React from 'react';
import InvestigationSummary from './report/InvestigationSummary';
import StatusBadge from './report/StatusBadge';
import DomainReport from './report/DomainReport';
import IPv4Report from './report/IPv4Report';
import RelatedInfrastructure from './report/RelatedInfrastructure';
import SectionNav from './report/SectionNav';
import InfrastructureGraph from './report/InfrastructureGraph';

export default function InvestigationResult({ result, onPivot, isInvestigating }) {
  if (!result) return null;

  const { target, status, investigation_id, duration_ms, started_at, completed_at, collector_status, collectors, correlation } = result;

  return (
    <div className="w-full text-left space-y-6 mt-8">
      {/* Navigation */}
      <SectionNav type={target?.type} collectors={collectors} correlation={correlation} organization={result.organization_footprint} />

      {/* Overview Section */}
      <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 className="text-2xl font-extrabold text-gray-900 mb-4 border-b border-gray-200 pb-3 flex flex-wrap justify-between items-center gap-4">
          <div>
            <span className="text-gray-500 font-medium text-lg mr-2">{target?.type === 'ipv4' ? 'Public IPv4:' : 'Domain:'}</span>
            <span className="text-blue-900">{target?.normalized}</span>
          </div>
          <div className="flex items-center gap-3 text-base font-medium">
            <span className="text-gray-600">Status:</span>
            <StatusBadge status={status} />
          </div>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm text-gray-700">
          <div>
            <span className="block text-gray-500 text-xs uppercase tracking-wider mb-1">Investigation ID</span>
            <span className="font-mono text-xs">{investigation_id}</span>
          </div>
          <div>
            <span className="block text-gray-500 text-xs uppercase tracking-wider mb-1">Duration</span>
            <span>{Math.round(duration_ms)} ms</span>
          </div>
          <div>
            <span className="block text-gray-500 text-xs uppercase tracking-wider mb-1">Started (UTC)</span>
            <span>{new Date(started_at).toISOString().replace('T', ' ').substring(0, 19)}</span>
          </div>
          <div>
            <span className="block text-gray-500 text-xs uppercase tracking-wider mb-1">Completed (UTC)</span>
            <span>{new Date(completed_at).toISOString().replace('T', ' ').substring(0, 19)}</span>
          </div>
        </div>
      </section>

      {/* Investigation Summary */}
      <InvestigationSummary target={target} collectors={collectors} correlation={correlation} />

      {/* Collector Statuses */}
      <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 className="text-xl font-bold text-gray-900 mb-4 border-b pb-2">Data Source Status</h3>
        <div className="flex flex-wrap gap-3">
          {collector_status && Object.entries(collector_status).map(([name, colStatus]) => (
            <div key={name} className="px-3 py-2 rounded bg-gray-50 border border-gray-200 flex items-center gap-3">
              <span className="capitalize font-medium text-gray-700 text-sm">{name.replace(/_/g, ' ')}</span>
              <StatusBadge status={colStatus} />
            </div>
          ))}
        </div>
      </section>

      {/* Interactive Infrastructure Graph */}
      <InfrastructureGraph correlation={correlation} onPivot={onPivot} isInvestigating={isInvestigating} />

      {/* Target Specific Report */}
      {target?.type === 'domain' && <DomainReport target={target} collectors={collectors} organization={result.organization_footprint} onPivot={onPivot} isInvestigating={isInvestigating} />}
      {target?.type === 'ipv4' && <IPv4Report target={target} collectors={collectors} organization={result.organization_footprint} onPivot={onPivot} isInvestigating={isInvestigating} />}

      {/* Related Infrastructure */}
      <RelatedInfrastructure correlation={correlation} onPivot={onPivot} isInvestigating={isInvestigating} />

      {/* Raw Data (Collapsed) */}
      <details className="bg-white p-4 rounded-xl shadow-sm border border-gray-100 group">
        <summary className="font-semibold text-gray-700 cursor-pointer hover:text-blue-600 transition-colors list-none flex items-center gap-2">
          <span className="transform group-open:rotate-90 transition-transform">▶</span>
          Technical Raw Data
        </summary>
        <div className="mt-4">
          <pre className="bg-gray-50 p-4 rounded-lg text-xs overflow-x-auto border border-gray-200 font-mono text-gray-700 max-h-96">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      </details>
    </div>
  );
}
