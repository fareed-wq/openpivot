import React from 'react';
import SectionCard from './SectionCard';

export default function InvestigationSummary({ target, collectors, correlation }) {
  if (!target || !collectors) return null;

  const isDomain = target.type === 'domain';
  
  // Domain collectors
  const rdap = collectors.rdap;
  const dns = collectors.dns;
  const email = collectors.email_security;
  const tls = collectors.tls;
  const httpMeta = collectors.http_metadata;
  
  // IPv4 collectors
  const ipCol = collectors.ip;
  const asn = collectors.asn;

  // Correlation
  const entityCount = correlation?.entities?.length;
  const relationCount = correlation?.relationships?.length;
  const infraValue = (entityCount !== undefined && relationCount !== undefined) 
    ? `${entityCount} entities \u00B7 ${relationCount} relationships`
    : 'Not available';

  // Domain values
  const registrar = rdap?.registrar?.name;

  let ipv4Count = 0;
  let ipv6Count = 0;
  let nsCount = 0;
  let mxCount = 0;

  if (dns?.records) {
    if (dns.records.A?.status === 'success' && dns.records.A.values) ipv4Count = dns.records.A.values.length;
    if (dns.records.AAAA?.status === 'success' && dns.records.AAAA.values) ipv6Count = dns.records.AAAA.values.length;
    if (dns.records.NS?.status === 'success' && dns.records.NS.values) nsCount = dns.records.NS.values.length;
    if (dns.records.MX?.status === 'success' && dns.records.MX.values) mxCount = dns.records.MX.values.length;
  }

  const tlsStatus = tls?.verification?.status === 'verified' ? 'Verified' : (tls?.status === 'success' ? 'Not Verified' : 'Unavailable');
  const httpsReachable = httpMeta?.status === 'success' ? (httpMeta.https?.reachable ? 'Reachable' : 'Unavailable') : 'Unavailable';

  const spfStatus = email?.spf?.status === 'present' ? 'Present' : (email?.spf?.status === 'absent' ? 'Absent' : 'Unavailable');
  const dmarcStatus = email?.dmarc?.status === 'present' ? 'Present' : (email?.dmarc?.status === 'absent' ? 'Absent' : 'Unavailable');

  // IPv4 values
  const hostname = ipCol?.reverse_dns?.hostname;
  const networkName = ipCol?.rdap?.name;
  const orgName = ipCol?.rdap?.organization?.name;
  const prefix = ipCol?.rdap?.network_prefixes?.[0];
  const asns = asn?.origin?.asns;
  const asnNum = asns?.length > 0 ? asns.map(a => `AS${a}`).join(', ') : null;
  const asnOrg = asn?.asn?.organization?.name;
  const regContext = ipCol?.rdap?.country || asn?.asn?.country;

  const SummaryRow = ({ label, value }) => {
    if (value === undefined || value === null || value === '') return null;
    return (
      <div>
        <span className="block text-gray-500 text-xs font-semibold uppercase tracking-wider mb-1">{label}</span>
        <span className="text-gray-900 font-medium">{value}</span>
      </div>
    );
  };

  return (
    <SectionCard title="Investigation Summary" collapsible={false}>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-y-6 gap-x-4">
        {isDomain ? (
          <>
            <SummaryRow label="Target" value={target.normalized} />
            <SummaryRow label="Registrar" value={registrar} />
            <SummaryRow label="IPv4" value={ipv4Count || '0'} />
            <SummaryRow label="IPv6" value={ipv6Count || '0'} />
            <SummaryRow label="Nameservers" value={nsCount || '0'} />
            <SummaryRow label="Mail Servers" value={mxCount || '0'} />
            <SummaryRow label="TLS" value={tlsStatus} />
            <SummaryRow label="HTTPS" value={httpsReachable} />
            <SummaryRow label="SPF" value={spfStatus} />
            <SummaryRow label="DMARC" value={dmarcStatus} />
          </>
        ) : (
          <>
            <SummaryRow label="IP Address" value={target.normalized} />
            <SummaryRow label="Reverse DNS" value={hostname} />
            <SummaryRow label="Network" value={networkName} />
            <SummaryRow label="Organization" value={orgName} />
            <SummaryRow label="Prefix" value={prefix} />
            <SummaryRow label="ASN" value={asnNum} />
            <SummaryRow label="ASN Organization" value={asnOrg} />
            <SummaryRow label="Registration Context" value={regContext} />
          </>
        )}
        <SummaryRow label="Infrastructure" value={infraValue} />
      </div>
    </SectionCard>
  );
}
