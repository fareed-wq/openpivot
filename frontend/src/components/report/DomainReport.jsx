import React from 'react';
import OrganizationFootprint from './OrganizationFootprint';
import SectionCard from './SectionCard';
import KeyValueRow from './KeyValueRow';
import StatusBadge from './StatusBadge';
import PivotButton from './PivotButton';
import CopyButton from './CopyButton';

export default function DomainReport({ target, collectors, onPivot, isInvestigating }) {
  const dns = collectors?.dns;
  const email = collectors?.email_security;
  const rdap = collectors?.rdap;
  const tls = collectors?.tls;
  const httpMeta = collectors?.http_metadata;

  const getDnsSubtitle = () => {
    if (!dns?.records) return null;
    const parts = [];
    ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'CAA'].forEach(t => {
      if (dns.records[t]?.status === 'success' && dns.records[t].values?.length) {
        parts.push(`${dns.records[t].values.length} ${t}`);
      }
    });
    return parts.length > 0 ? parts.join(' \u00B7 ') : null;
  };

  return (
    <div className="space-y-6">
      {/* Domain Overview */}
      <SectionCard id="sec-overview" title="Domain Overview">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
          <KeyValueRow label="Domain" value={<div className="flex items-center gap-1"><span>{target.normalized}</span><CopyButton text={target.normalized} /></div>} />
          {rdap?.registrar?.name && <KeyValueRow label="Registrar" value={rdap.registrar.name} />}
          {rdap?.registration_date && <KeyValueRow label="Registration Date" value={new Date(rdap.registration_date).toLocaleString()} />}
          {rdap?.expiration_date && <KeyValueRow label="Expiration Date" value={new Date(rdap.expiration_date).toLocaleString()} />}
          {httpMeta?.status === 'success' && <KeyValueRow label="HTTPS Reachable" value={httpMeta.https?.reachable ? 'Yes' : 'No'} />}
          {httpMeta?.status === 'success' && httpMeta.https?.reachable && <KeyValueRow label="HTTP Status" value={httpMeta.status_code} />}
          {httpMeta?.status === 'success' && httpMeta.https?.reachable && <KeyValueRow label="Page Title" value={httpMeta.title || 'No title'} />}
        </div>
      </SectionCard>


      {/* Web Footprint Intelligence */}
      {httpMeta?.web_footprint && (
        <SectionCard id="sec-web" title="Web Footprint Intelligence" status={<StatusBadge status={httpMeta.status} />} collapsible={true} defaultOpen={false} subtitle={httpMeta.web_footprint.technology_count ? `${httpMeta.web_footprint.technology_count} technologies detected` : null}>
          <div className="space-y-6 text-sm">
            {/* Web Metadata */}
            {httpMeta.web_footprint.metadata && Object.keys(httpMeta.web_footprint.metadata).length > 0 && (
              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Web Metadata</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {httpMeta.web_footprint.metadata.title && <KeyValueRow label="Page Title" value={httpMeta.web_footprint.metadata.title} className="col-span-1 md:col-span-2" />}
                  {httpMeta.web_footprint.metadata.description && <KeyValueRow label="Description" value={httpMeta.web_footprint.metadata.description} className="col-span-1 md:col-span-2" />}
                  {httpMeta.web_footprint.metadata.canonical_url && (
                    <KeyValueRow label="Canonical URL" value={
                      <div className="flex items-center gap-1">
                        <span className="break-all">{httpMeta.web_footprint.metadata.canonical_url}</span>
                        <CopyButton text={httpMeta.web_footprint.metadata.canonical_url} />
                      </div>
                    } className="col-span-1 md:col-span-2" />
                  )}
                  {httpMeta.web_footprint.metadata.generator && <KeyValueRow label="Generator" value={httpMeta.web_footprint.metadata.generator} />}
                  {httpMeta.web_footprint.metadata.favicon_url && (
                    <KeyValueRow label="Favicon URL" value={
                      <div className="flex items-center gap-1">
                        <span className="break-all">{httpMeta.web_footprint.metadata.favicon_url}</span>
                        <CopyButton text={httpMeta.web_footprint.metadata.favicon_url} />
                      </div>
                    } />
                  )}
                  {httpMeta.web_footprint.metadata.language && <KeyValueRow label="Language" value={httpMeta.web_footprint.metadata.language} />}
                </div>
              </div>
            )}

            {/* Detected Technologies */}
            {httpMeta.web_footprint.technologies?.length > 0 ? (
              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Detected Technologies</h4>
                <div className="space-y-2">
                  {httpMeta.web_footprint.technologies.map((tech, idx) => (
                    <div key={idx} className="bg-gray-50 p-3 rounded border border-gray-200">
                      <div className="flex flex-wrap justify-between items-start gap-2">
                        <div>
                          <span className="font-semibold text-gray-900">{tech.name}</span>
                          <span className="ml-2 text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">{tech.category}</span>
                        </div>
                        <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                          tech.confidence === 'high' ? 'bg-green-100 text-green-800' :
                          tech.confidence === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-gray-100 text-gray-600'
                        }`}>
                          {tech.confidence}
                        </span>
                      </div>
                      <div className="mt-1 text-xs text-gray-600 break-all">
                        <span className="text-gray-500">Evidence:</span> {tech.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="text-gray-500">No technologies detected from available signals.</div>
            )}
          </div>
        </SectionCard>
      )}

      {/* Organization Footprint */}
      <OrganizationFootprint organization={organization} onPivot={onPivot} isInvestigating={isInvestigating} />

      {/* DNS Intelligence */}
      {dns && (
        <SectionCard id="sec-dns" title="DNS Intelligence" status={<StatusBadge status={dns.status} />} collapsible={true} defaultOpen={false} subtitle={getDnsSubtitle()}>
          {dns.status === 'success' ? (
            <div className="space-y-4">
              {['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'CAA'].map(recordType => {
                const recordData = dns.records?.[recordType];
                if (!recordData) return null;

                return (
                  <div key={recordType} className="border-l-2 border-gray-200 pl-4 py-1">
                    <h4 className="font-semibold text-gray-800 mb-1">{recordType} Records</h4>
                    {recordData.status === 'no_answer' ? (
                      <div className="text-sm text-gray-500">No record returned</div>
                    ) : recordData.status !== 'success' ? (
                      <div className="text-sm text-red-600">Error: {recordData.status}</div>
                    ) : (
                      <div className="text-sm text-gray-700 flex flex-wrap gap-2">
                        {recordData.values?.map((val, idx) => {
                          if (recordType === 'MX' && typeof val === 'object' && val !== null) {
                            return (
                              <div key={idx} className="bg-gray-50 px-2 py-1 rounded border border-gray-200 flex items-center">
                                <span>Priority {val.priority ?? val.preference}: {val.host ?? val.exchange}</span>
                                {val.host && <CopyButton text={val.host} />}
                                {val.host && <PivotButton target={val.host} onPivot={onPivot} disabled={isInvestigating} />}
                              </div>
                            );
                          } else if (recordType === 'CAA' && typeof val === 'object' && val !== null) {
                            return (
                              <div key={idx} className="bg-gray-50 px-3 py-2 rounded border border-gray-200 w-full md:w-auto flex items-center">
                                <span className="text-gray-500 mr-2">Flags: {val.flags}</span>
                                <span className="text-gray-500 mr-2">Tag: {val.tag}</span>
                                <span className="font-mono break-all">{val.value}</span>
                              </div>
                            );
                          } else if (recordType === 'TXT') {
                            const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
                            return <div key={idx} className="bg-gray-50 px-3 py-2 rounded border border-gray-200 w-full break-all whitespace-pre-wrap flex items-center">{displayVal}</div>;
                          } else {
                            const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
                            return (
                              <div key={idx} className="bg-gray-50 px-2 py-1 rounded border border-gray-200 flex items-center">
                                <span>{displayVal}</span>
                                {(recordType === 'A' || recordType === 'AAAA' || recordType === 'NS') && <CopyButton text={String(val)} />}
                                {(recordType === 'A' || recordType === 'NS') && <PivotButton target={String(val)} onPivot={onPivot} disabled={isInvestigating} />}
                              </div>
                            );
                          }
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-sm text-gray-600">DNS intelligence collection encountered an issue: {dns.error || dns.status}</div>
          )}
        </SectionCard>
      )}

      {/* Email Security */}
      {email && (
        <SectionCard id="sec-email" title="Email Security" status={<StatusBadge status={email.status} />} collapsible={true} defaultOpen={false}>
          {email.status === 'success' ? (
            <div className="grid grid-cols-1 gap-4 text-sm">
              <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                <h4 className="font-semibold text-gray-800 mb-2">SPF</h4>
                <div className="text-gray-700 mb-2">Status: <span className="font-medium">{email.spf?.status === 'present' ? 'Present' : email.spf?.status === 'absent' ? 'Absent' : 'Unavailable'}</span></div>
                {email.spf?.record && <div className="text-gray-600 break-all">{email.spf.record}</div>}
              </div>

              <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                <h4 className="font-semibold text-gray-800 mb-2">DMARC</h4>
                <div className="text-gray-700 mb-2">Status: <span className="font-medium">{email.dmarc?.status === 'present' ? 'Present' : email.dmarc?.status === 'absent' ? 'Absent' : 'Unavailable'}</span></div>
                {email.dmarc?.record && <div className="text-gray-600 break-all">{email.dmarc.record}</div>}
              </div>

              {email.mx_providers?.length > 0 && (
                <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                  <h4 className="font-semibold text-gray-800 mb-2">MX Providers</h4>
                  <ul className="list-disc list-inside text-gray-700">
                    {email.mx_providers.map((mx, idx) => (
                      <li key={idx}>Priority {mx.preference}: {mx.host} {mx.provider ? `(${mx.provider})` : ''}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-gray-600">Email security collection encountered an issue: {email.error || email.status}</div>
          )}
        </SectionCard>
      )}

      {/* RDAP */}
      {rdap && (
        <SectionCard id="sec-rdap" title="Registration Information (RDAP)" status={<StatusBadge status={rdap.status} />} collapsible={true} defaultOpen={false}>
          {rdap.status === 'success' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
              <KeyValueRow label="Registrar" value={rdap.registrar.name} />
              <KeyValueRow label="Handle" value={<div className="flex items-center gap-1"><span>{rdap.handle}</span><CopyButton text={rdap.handle} /></div>} />
              <KeyValueRow label="Registration Date" value={rdap.registration_date ? new Date(rdap.registration_date).toLocaleString() : null} />
              <KeyValueRow label="Expiration Date" value={rdap.expiration_date ? new Date(rdap.expiration_date).toLocaleString() : null} />
              <KeyValueRow label="Last Changed" value={rdap.last_changed_date ? new Date(rdap.last_changed_date).toLocaleString() : null} />
              <KeyValueRow label="Organization" value={rdap.organization?.name} />

              {rdap.nameservers?.length > 0 && (
                <div className="col-span-1 md:col-span-2 mt-2">
                  <span className="font-semibold text-gray-700 block mb-1">Nameservers:</span>
                  <div className="flex flex-wrap gap-2">
                    {rdap.nameservers.map((ns, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{ns}</span>
                    ))}
                  </div>
                </div>
              )}

              {rdap.domain_statuses?.length > 0 && (
                <div className="col-span-1 md:col-span-2 mt-2">
                  <span className="font-semibold text-gray-700 block mb-1">Domain Statuses:</span>
                  <div className="flex flex-wrap gap-2">
                    {rdap.domain_statuses.map((st, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{st}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-gray-600">RDAP collection encountered an issue: {rdap.error || rdap.status}</div>
          )}
        </SectionCard>
      )}

      {/* TLS Certificate */}
      {tls && (
        <SectionCard id="sec-tls" title="Certificate Information (TLS)" status={<StatusBadge status={tls.status} />} collapsible={true} defaultOpen={false}>
          {tls.status === 'success' && tls.certificate ? (
            <div className="space-y-6 text-sm">
              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Connection & Verification</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <KeyValueRow label="Peer IP" value={tls.peer_ip} />
                  <KeyValueRow label="Port" value={tls.port} />
                  <KeyValueRow label="TLS Version" value={tls.tls_version} />
                  <KeyValueRow label="Cipher" value={tls.cipher} />
                  <KeyValueRow label="Verified" value={tls.verification?.status === 'verified' ? 'Yes' : 'No'} />
                  {tls.verification?.status !== 'verified' && <KeyValueRow label="Verification Error" value={tls.verification?.reason} />}
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Certificate</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <KeyValueRow label="Subject" value={tls.certificate.subject} className="col-span-1 md:col-span-2" />
                  <KeyValueRow label="Issuer" value={tls.certificate.issuer} className="col-span-1 md:col-span-2" />
                  <KeyValueRow label="Valid From" value={tls.certificate.not_before ? new Date(tls.certificate.not_before).toLocaleString() : null} />
                  <KeyValueRow label="Valid Until" value={tls.certificate.not_after ? new Date(tls.certificate.not_after).toLocaleString() : null} />
                  <KeyValueRow label="Currently Valid" value={tls.certificate.currently_valid ? 'Yes' : 'No'} />
                  <KeyValueRow label="Days Until Expiry" value={tls.certificate.days_until_expiry} />
                  <KeyValueRow label="Serial Number" value={tls.certificate.serial_number} />
                  <KeyValueRow label="Version" value={tls.certificate.version} />
                </div>
                <div className="mt-3">
                  <span className="font-semibold text-gray-700 block mb-1">SHA-256 Fingerprint:</span>
                  <div className="bg-gray-50 p-2 border border-gray-200 rounded font-mono text-xs break-all text-gray-600">
                    <div className="flex items-center gap-2"><span>{tls.certificate.sha256_fingerprint}</span><CopyButton text={tls.certificate.sha256_fingerprint} /></div>
                  </div>
                </div>
              </div>

              {tls.certificate.san_dns?.length > 0 && (
                <div>
                  <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Subject Alternative Names (DNS)</h4>
                  <div className="flex flex-wrap gap-2">
                    {tls.certificate.san_dns.map((san, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{san}</span>
                    ))}
                  </div>
                </div>
              )}

              {tls.certificate.san_ip?.length > 0 && (
                <div>
                  <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Subject Alternative Names (IP)</h4>
                  <div className="flex flex-wrap gap-2">
                    {tls.certificate.san_ip.map((san, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{san}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-sm text-gray-600">TLS collection encountered an issue: {tls.error || tls.status}</div>
          )}
        </SectionCard>
      )}

      {/* HTTP Metadata */}
      {httpMeta && (
        <SectionCard id="sec-http" title="HTTP Metadata" status={<StatusBadge status={httpMeta.status} />} collapsible={true} defaultOpen={false}>
          {httpMeta.status === 'success' ? (
            <div className="space-y-4 text-sm">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <KeyValueRow label="Final URL" value={httpMeta.final_url} className="col-span-1 md:col-span-2" />
                <KeyValueRow label="Status Code" value={httpMeta.status_code} />
                <KeyValueRow label="Scheme" value={httpMeta.scheme} />
                <KeyValueRow label="Hostname" value={httpMeta.hostname} />
                <KeyValueRow label="Peer IP" value={httpMeta.peer_ip} />
                <KeyValueRow label="HTTPS Reachable" value={httpMeta.https?.reachable ? 'Yes' : 'No'} />
                <KeyValueRow label="HTTPS Verified" value={httpMeta.https?.verified ? 'Yes' : 'No'} />
                <KeyValueRow label="Page Title" value={httpMeta.title} className="col-span-1 md:col-span-2" />
              </div>

              {httpMeta.headers && Object.keys(httpMeta.headers).length > 0 && (
                <div>
                  <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Selected Headers</h4>
                  <div className="grid grid-cols-1 gap-1">
                    {['server', 'content-type', 'content-length', 'content-language', 'via', 'x-powered-by'].map(h => {
                      if (httpMeta.headers[h]) {
                        return <KeyValueRow key={h} label={h.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-')} value={httpMeta.headers[h]} />;
                      }
                      return null;
                    })}
                  </div>
                </div>
              )}

              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Redirects</h4>
                {httpMeta.redirects?.length > 0 ? (
                  <div className="space-y-2">
                    {httpMeta.redirects.map((red, idx) => (
                      <div key={idx} className="bg-gray-50 p-2 border border-gray-200 rounded">
                        <div className="font-mono text-xs text-gray-700">
                          <span className="font-semibold text-blue-600">{red.status_code}</span> from <span className="break-all">{red.from_url}</span> <br/>
                          → to <span className="break-all">{red.to_url}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-gray-500">No redirects</div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-sm text-gray-600">HTTP metadata collection encountered an issue: {httpMeta.error || httpMeta.status}</div>
          )}
        </SectionCard>
      )}
    </div>
  );
}
