import React from 'react';
import OrganizationFootprint from './OrganizationFootprint';
import SectionCard from './SectionCard';
import KeyValueRow from './KeyValueRow';
import StatusBadge from './StatusBadge';
import PivotButton from './PivotButton';
import CopyButton from './CopyButton';

export default function IPv4Report({ target, collectors, organization, onPivot, isInvestigating }) {
  const ip = collectors?.ip;
  const asn = collectors?.asn;

  return (
    <div className="space-y-6">
      {/* IP Overview */}
      <SectionCard id="sec-overview" title="IP Overview">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
          <KeyValueRow label="IP Address" value={<div className="flex items-center gap-1"><span>{target.normalized}</span><CopyButton text={target.normalized} /></div>} />
          {ip?.reverse_dns?.status === 'success' && ip.reverse_dns.hostname && (
            <div className="flex items-center gap-2 col-span-1 md:col-span-2">
              <KeyValueRow label="Reverse DNS Hostname" value={ip.reverse_dns.hostname} />
              <PivotButton target={ip.reverse_dns.hostname} onPivot={onPivot} disabled={isInvestigating} />
            </div>
          )}
          {ip?.rdap?.name && <KeyValueRow label="Network Name" value={ip.rdap.name} />}
          {ip?.rdap?.organization?.name && <KeyValueRow label="Organization" value={ip.rdap.organization.name} />}
          {ip?.rdap?.network_prefixes?.[0] && <KeyValueRow label="Network Prefix" value={ip.rdap.network_prefixes.join(', ')} />}
          {ip?.rdap?.country && <KeyValueRow label="Network Registration Context" value={ip.rdap.country} />}
          {asn?.asn?.handle && <KeyValueRow label="ASN" value={asn.asn.handle} />}
        </div>
      </SectionCard>

      {/* Network RDAP */}
      {ip && (
        <SectionCard id="sec-rdap" title="Network Allocation (RDAP)" status={<StatusBadge status={ip.status} />} collapsible={true} defaultOpen={false}>
          {ip.status === 'success' && ip.rdap ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
              <KeyValueRow label="Handle" value={<div className="flex items-center gap-1"><span>{ip.rdap.handle}</span><CopyButton text={ip.rdap.handle} /></div>} />
              <KeyValueRow label="Network Name" value={ip.rdap.name} />
              <KeyValueRow label="Start Address" value={ip.rdap.start_address} />
              <KeyValueRow label="End Address" value={ip.rdap.end_address} />
              <KeyValueRow label="IP Version" value={ip.rdap.ip_version} />
              <KeyValueRow label="Type" value={ip.rdap.type} />
              <KeyValueRow label="Country/Allocation Context" value={ip.rdap.country} />
              <KeyValueRow label="Parent Handle" value={ip.rdap.parent_handle} />
              <KeyValueRow label="Registration Date" value={ip.rdap.registration_date ? new Date(ip.rdap.registration_date).toLocaleString() : null} />
              <KeyValueRow label="Last Changed" value={ip.rdap.last_changed_date ? new Date(ip.rdap.last_changed_date).toLocaleString() : null} />
              <KeyValueRow label="Organization" value={ip.rdap.organization?.name} />
              <KeyValueRow label="RDAP Source" value={ip.rdap.source} className="col-span-1 md:col-span-2 break-all" />

              {ip.rdap.statuses?.length > 0 && (
                <div className="col-span-1 md:col-span-2 mt-2">
                  <span className="font-semibold text-gray-700 block mb-1">Statuses:</span>
                  <div className="flex flex-wrap gap-2">
                    {ip.rdap.statuses.map((st, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{st}</span>
                    ))}
                  </div>
                </div>
              )}

              {ip.rdap.network_prefixes?.length > 0 && (
                <div className="col-span-1 md:col-span-2 mt-2">
                  <span className="font-semibold text-gray-700 block mb-1">Network Prefixes:</span>
                  <div className="flex flex-wrap gap-2">
                    {ip.rdap.network_prefixes.map((p, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800 font-mono text-xs">{p}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-gray-600">IP intelligence collection encountered an issue: {ip?.error || ip?.status}</div>
          )}
        </SectionCard>
      )}

      {/* Reverse DNS */}
      {ip && (
        <SectionCard id="sec-reversedns" title="Reverse DNS" collapsible={true} defaultOpen={false}>
          <div className="text-sm">
            {ip.reverse_dns?.status === 'success' ? (
              ip.reverse_dns.hostname ? (
                <div className="flex items-center gap-2">
                  <KeyValueRow label="Hostname" value={<div className="flex items-center gap-1"><span>{ip.reverse_dns.hostname}</span><CopyButton text={ip.reverse_dns.hostname} /></div>} />
                  <PivotButton target={ip.reverse_dns.hostname} onPivot={onPivot} disabled={isInvestigating} />
                </div>
              ) : (
                <div className="text-gray-500">No PTR record returned</div>
              )
            ) : (
              <div className="text-gray-600">Reverse DNS collection encountered an issue: {ip.reverse_dns?.status || 'Unknown'}</div>
            )}
          </div>
        </SectionCard>
      )}

      {/* ASN Intelligence */}
      {asn && (
        <SectionCard id="sec-asn" title="Routing Information (ASN)" status={<StatusBadge status={asn.status} />} collapsible={true} defaultOpen={false}>
          {asn.status === 'success' ? (
            <div className="space-y-6 text-sm">
              {asn.origin && (
                <div>
                  <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">BGP Origin</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <KeyValueRow label="Origin ASN(s)" value={asn.origin.asns?.join(', ')} />
                    <KeyValueRow label="BGP Prefix" value={asn.origin.prefix} />
                    <KeyValueRow label="Registry" value={asn.origin.registry} />
                    <KeyValueRow label="Country/Registration Context" value={asn.origin.country} />
                    <KeyValueRow label="Allocation Date" value={asn.origin.allocated} />
                  </div>
                </div>
              )}

              {asn.asn && (
                <div>
                  <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">ASN Registration</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    <KeyValueRow label="ASN Number" value={<div className="flex items-center gap-1"><span>{asn.asn.number}</span><CopyButton text={asn.asn.number} /></div>} />
                    <KeyValueRow label="ASN Name" value={asn.asn.name} />
                    <KeyValueRow label="Handle" value={asn.asn.handle} />
                    <KeyValueRow label="Start ASN" value={asn.asn.start_autnum} />
                    <KeyValueRow label="End ASN" value={asn.asn.end_autnum} />
                    <KeyValueRow label="Type" value={asn.asn.type} />
                    <KeyValueRow label="Country" value={asn.asn.country} />
                    <KeyValueRow label="Registration Date" value={asn.asn.registration_date ? new Date(asn.asn.registration_date).toLocaleString() : null} />
                    <KeyValueRow label="Last Changed" value={asn.asn.last_changed_date ? new Date(asn.asn.last_changed_date).toLocaleString() : null} />
                    <KeyValueRow label="Organization" value={asn.asn.organization?.name} />
                    <KeyValueRow label="RDAP Source" value={asn.asn.source} className="col-span-1 md:col-span-2 break-all" />

                    {asn.asn.statuses?.length > 0 && (
                      <div className="col-span-1 md:col-span-2 mt-2">
                        <span className="font-semibold text-gray-700 block mb-1">Statuses:</span>
                        <div className="flex flex-wrap gap-2">
                          {asn.asn.statuses.map((st, idx) => (
                            <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{st}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-gray-600">ASN intelligence collection encountered an issue: {asn.error || asn.status}</div>
          )}
        </SectionCard>
      )}
    </div>
  );
}
