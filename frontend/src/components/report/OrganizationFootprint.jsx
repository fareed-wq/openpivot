import React from 'react';
import SectionCard from './SectionCard';
import KeyValueRow from './KeyValueRow';
import CopyButton from './CopyButton';
import PivotButton from './PivotButton';

export default function OrganizationFootprint({ organization, onPivot, isInvestigating }) {
  if (!organization || !organization.counts || !Object.values(organization.counts).some(v => v > 0)) return null;

  return (
    <SectionCard id="sec-org" title="Organization Technical Footprint" collapsible={true} defaultOpen={false}>
      <div className="space-y-6 text-sm">

        {/* Organizations */}
        {organization.organizations?.length > 0 && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-3 border-b pb-1">Observed Organizations</h4>
            <div className="space-y-3">
              {organization.organizations.map((org, idx) => (
                <div key={idx} className="bg-gray-50 p-3 rounded border border-gray-200">
                  <div className="flex flex-wrap justify-between items-start gap-2 mb-2">
                    <span className="font-semibold text-gray-900 text-base">{org.name}</span>
                    {org.context && (
                      <span className="text-xs font-medium px-2 py-0.5 bg-blue-100 text-blue-800 rounded" title="Registration Context">
                        {org.context}
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-gray-600">
                    <span className="font-medium text-gray-500 mr-2">Sources:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {org.sources?.map((s, i) => (
                        <span key={i} className="bg-white border border-gray-200 px-2 py-0.5 rounded text-gray-600">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Associated Infrastructure */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

          {/* ASNs */}
          {organization.asns?.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Associated ASNs</h4>
              <div className="flex flex-wrap gap-2">
                {organization.asns.map(asn => (
                  <div key={asn} className="flex items-center gap-1 bg-gray-50 px-2 py-1 rounded border border-gray-200">
                    <span className="font-mono text-xs">AS{asn}</span>
                    <CopyButton text={asn} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Prefixes */}
          {organization.prefixes?.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Network Prefixes</h4>
              <div className="flex flex-wrap gap-2">
                {organization.prefixes.map(prefix => (
                  <div key={prefix} className="flex items-center gap-1 bg-gray-50 px-2 py-1 rounded border border-gray-200">
                    <span className="font-mono text-xs">{prefix}</span>
                    <CopyButton text={prefix} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* IPs */}
          {organization.ips?.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Associated IPv4</h4>
              <div className="flex flex-wrap gap-2">
                {organization.ips.map(ip => (
                  <div key={ip} className="flex items-center gap-1 bg-gray-50 px-2 py-1 rounded border border-gray-200">
                    <span className="font-mono text-xs">{ip}</span>
                    <CopyButton text={ip} />
                    <PivotButton target={ip} type="ipv4" onPivot={onPivot} disabled={isInvestigating} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Nameservers */}
          {organization.nameservers?.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Nameservers</h4>
              <div className="flex flex-col gap-2">
                {organization.nameservers.map(ns => (
                  <div key={ns} className="flex items-center justify-between bg-gray-50 px-2 py-1 rounded border border-gray-200">
                    <span className="font-mono text-xs truncate mr-2">{ns}</span>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <CopyButton text={ns} />
                      <PivotButton target={ns} type="domain" onPivot={onPivot} disabled={isInvestigating} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Mail Hosts */}
          {organization.mail_hosts?.length > 0 && (
            <div>
              <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Mail Hosts</h4>
              <div className="flex flex-col gap-2">
                {organization.mail_hosts.map(mx => (
                  <div key={mx} className="flex items-center justify-between bg-gray-50 px-2 py-1 rounded border border-gray-200">
                    <span className="font-mono text-xs truncate mr-2">{mx}</span>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <CopyButton text={mx} />
                      <PivotButton target={mx} type="domain" onPivot={onPivot} disabled={isInvestigating} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Technologies summary */}
        {organization.technologies?.length > 0 && (
          <div>
            <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Technology Stack</h4>
            <div className="flex flex-wrap gap-2">
              {organization.technologies.map((tech, idx) => (
                <span key={idx} className="bg-gray-100 px-2 py-1 rounded text-xs text-gray-700 font-medium border border-gray-200">
                  {tech.name} <span className="text-gray-400 font-normal ml-1">({tech.category})</span>
                </span>
              ))}
            </div>
          </div>
        )}

      </div>
    </SectionCard>
  );
}
