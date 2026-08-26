import React from 'react';
import SectionCard from './SectionCard';
import KeyValueRow from './KeyValueRow';
import StatusBadge from './StatusBadge';

export default function DomainReport({ target, collectors }) {
  const dns = collectors?.dns;
  const email = collectors?.email_security;
  const rdap = collectors?.rdap;
  const tls = collectors?.tls;
  const httpMeta = collectors?.http_metadata;

  return (
    <div className="space-y-6">
      {/* Domain Overview */}
      <SectionCard title="Domain Overview">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
          <KeyValueRow label="Domain" value={target.normalized} />
          {rdap?.rdap?.registrar && <KeyValueRow label="Registrar" value={rdap.rdap.registrar} />}
          {rdap?.rdap?.registration_date && <KeyValueRow label="Registration Date" value={new Date(rdap.rdap.registration_date).toLocaleString()} />}
          {rdap?.rdap?.expiration_date && <KeyValueRow label="Expiration Date" value={new Date(rdap.rdap.expiration_date).toLocaleString()} />}
          {httpMeta?.status === 'success' && <KeyValueRow label="HTTPS Reachable" value={httpMeta.reachable ? 'Yes' : 'No'} />}
          {httpMeta?.status === 'success' && httpMeta.reachable && <KeyValueRow label="HTTP Status" value={httpMeta.status_code} />}
          {httpMeta?.status === 'success' && httpMeta.reachable && <KeyValueRow label="Page Title" value={httpMeta.title || 'No title'} />}
        </div>
      </SectionCard>

      {/* DNS Intelligence */}
      {dns && (
        <SectionCard title="DNS Intelligence" status={<StatusBadge status={dns.status} />}>
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
                            return <div key={idx} className="bg-gray-50 px-2 py-1 rounded border border-gray-200">Priority {val.priority ?? val.preference}: {val.host ?? val.exchange}</div>;
                          } else if (recordType === 'CAA' && typeof val === 'object' && val !== null) {
                            return (
                              <div key={idx} className="bg-gray-50 px-3 py-2 rounded border border-gray-200 w-full md:w-auto">
                                <span className="text-gray-500 mr-2">Flags: {val.flags}</span>
                                <span className="text-gray-500 mr-2">Tag: {val.tag}</span>
                                <span className="font-mono break-all">{val.value}</span>
                              </div>
                            );
                          } else if (recordType === 'TXT') {
                            const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
                            return <div key={idx} className="bg-gray-50 px-3 py-2 rounded border border-gray-200 w-full break-all whitespace-pre-wrap">{displayVal}</div>;
                          } else {
                            const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
                            return <div key={idx} className="bg-gray-50 px-2 py-1 rounded border border-gray-200">{displayVal}</div>;
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
        <SectionCard title="Email Security" status={<StatusBadge status={email.status} />}>
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
        <SectionCard title="Registration Information (RDAP)" status={<StatusBadge status={rdap.status} />}>
          {rdap.status === 'success' && rdap.rdap ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
              <KeyValueRow label="Registrar" value={rdap.rdap.registrar} />
              <KeyValueRow label="Handle" value={rdap.rdap.handle} />
              <KeyValueRow label="Registration Date" value={rdap.rdap.registration_date ? new Date(rdap.rdap.registration_date).toLocaleString() : null} />
              <KeyValueRow label="Expiration Date" value={rdap.rdap.expiration_date ? new Date(rdap.rdap.expiration_date).toLocaleString() : null} />
              <KeyValueRow label="Last Changed" value={rdap.rdap.last_changed_date ? new Date(rdap.rdap.last_changed_date).toLocaleString() : null} />
              <KeyValueRow label="Organization" value={rdap.rdap.organization} />
              
              {rdap.rdap.nameservers?.length > 0 && (
                <div className="col-span-1 md:col-span-2 mt-2">
                  <span className="font-semibold text-gray-700 block mb-1">Nameservers:</span>
                  <div className="flex flex-wrap gap-2">
                    {rdap.rdap.nameservers.map((ns, idx) => (
                      <span key={idx} className="bg-gray-100 px-2 py-1 rounded border border-gray-200 text-gray-800">{ns}</span>
                    ))}
                  </div>
                </div>
              )}

              {rdap.rdap.statuses?.length > 0 && (
                <div className="col-span-1 md:col-span-2 mt-2">
                  <span className="font-semibold text-gray-700 block mb-1">Domain Statuses:</span>
                  <div className="flex flex-wrap gap-2">
                    {rdap.rdap.statuses.map((st, idx) => (
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
        <SectionCard title="Certificate Information (TLS)" status={<StatusBadge status={tls.status} />}>
          {tls.status === 'success' && tls.certificate ? (
            <div className="space-y-6 text-sm">
              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Connection & Verification</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <KeyValueRow label="Peer IP" value={tls.peer_ip} />
                  <KeyValueRow label="Port" value={tls.port} />
                  <KeyValueRow label="TLS Version" value={tls.tls_version} />
                  <KeyValueRow label="Cipher" value={tls.cipher} />
                  <KeyValueRow label="Verified" value={tls.certificate.verified ? 'Yes' : 'No'} />
                  {!tls.certificate.verified && <KeyValueRow label="Verification Error" value={tls.certificate.verification_error} />}
                </div>
              </div>
              
              <div>
                <h4 className="font-semibold text-gray-800 mb-2 border-b pb-1">Certificate</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <KeyValueRow label="Subject" value={tls.certificate.subject} className="col-span-1 md:col-span-2" />
                  <KeyValueRow label="Issuer" value={tls.certificate.issuer} className="col-span-1 md:col-span-2" />
                  <KeyValueRow label="Valid From" value={tls.certificate.not_before ? new Date(tls.certificate.not_before).toLocaleString() : null} />
                  <KeyValueRow label="Valid Until" value={tls.certificate.not_after ? new Date(tls.certificate.not_after).toLocaleString() : null} />
                  <KeyValueRow label="Currently Valid" value={tls.certificate.is_valid ? 'Yes' : 'No'} />
                  <KeyValueRow label="Days Until Expiry" value={tls.certificate.days_until_expiry} />
                  <KeyValueRow label="Serial Number" value={tls.certificate.serial_number} />
                  <KeyValueRow label="Version" value={tls.certificate.version} />
                </div>
                <div className="mt-3">
                  <span className="font-semibold text-gray-700 block mb-1">SHA-256 Fingerprint:</span>
                  <div className="bg-gray-50 p-2 border border-gray-200 rounded font-mono text-xs break-all text-gray-600">
                    {tls.certificate.sha256_fingerprint}
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
        <SectionCard title="HTTP Metadata" status={<StatusBadge status={httpMeta.status} />}>
          {httpMeta.status === 'success' ? (
            <div className="space-y-4 text-sm">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <KeyValueRow label="Final URL" value={httpMeta.url} className="col-span-1 md:col-span-2" />
                <KeyValueRow label="Status Code" value={httpMeta.status_code} />
                <KeyValueRow label="Scheme" value={httpMeta.scheme} />
                <KeyValueRow label="Hostname" value={httpMeta.hostname} />
                <KeyValueRow label="Peer IP" value={httpMeta.peer_ip} />
                <KeyValueRow label="HTTPS Reachable" value={httpMeta.reachable ? 'Yes' : 'No'} />
                <KeyValueRow label="HTTPS Verified" value={httpMeta.verified ? 'Yes' : 'No'} />
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
