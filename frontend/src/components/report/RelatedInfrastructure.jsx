import React from 'react';
import SectionCard from './SectionCard';

const TYPE_LABELS = {
  resolves_to: 'Resolves to',
  uses_nameserver: 'Uses nameserver',
  uses_mail_server: 'Uses mail server',
  presents_certificate: 'Presents certificate',
  contains_hostname: 'Contains hostname',
  reverse_resolves_to: 'Reverse resolves to',
  announced_by: 'Announced by',
  registered_to: 'Registered to'
};

const formatRelType = (type) => TYPE_LABELS[type] || type.replace(/_/g, ' ');

export default function RelatedInfrastructure({ correlation }) {
  if (!correlation) return null;
  const { entities = [], relationships = [] } = correlation;

  const groupedEntities = entities.reduce((acc, e) => {
    acc[e.type] = acc[e.type] || [];
    acc[e.type].push(e);
    return acc;
  }, {});

  const typeDisplayNames = {
    domain: 'Domains',
    hostname: 'Hostnames',
    ip: 'IP Addresses',
    asn: 'ASNs',
    organization: 'Organizations',
    nameserver: 'Nameservers',
    mail_server: 'Mail Servers',
    certificate: 'Certificates'
  };

  return (
    <SectionCard
      title="Related Infrastructure"
      collapsible={true}
      defaultOpen={false}
      subtitle={`${entities.length} entities \u00B7 ${relationships.length} relationships`}
    >
      <div className="text-sm text-gray-700 mb-6 flex gap-4">
        <div className="bg-gray-50 px-4 py-2 rounded-lg border border-gray-200">
          <span className="font-semibold text-gray-900 text-lg">{entities.length}</span> Entities
        </div>
        <div className="bg-gray-50 px-4 py-2 rounded-lg border border-gray-200">
          <span className="font-semibold text-gray-900 text-lg">{relationships.length}</span> Relationships
        </div>
      </div>

      {relationships.length > 0 && (
        <div className="mb-8">
          <h4 className="font-semibold text-gray-900 mb-3 border-b pb-1">Relationships</h4>
          <div className="space-y-2">
            {relationships.map((r, idx) => {
              // Extract the value from ID to display (e.g. "domain:example.com" -> "example.com")
              // Or find the entity to get its value
              const sourceEntity = entities.find(e => e.id === r.source);
              const targetEntity = entities.find(e => e.id === r.target);

              const sourceValue = sourceEntity ? sourceEntity.value : r.source;
              const targetValue = targetEntity ? targetEntity.value : r.target;

              return (
                <div key={idx} className="text-sm bg-gray-50 p-2 rounded border border-gray-200 flex flex-wrap items-center gap-x-2">
                  <span className="font-medium text-gray-800 break-all">{sourceValue}</span>
                  <span className="text-blue-600 text-xs uppercase tracking-wider">{formatRelType(r.type)}</span>
                  <span className="font-medium text-gray-800 break-all">{targetValue}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {Object.keys(groupedEntities).length > 0 && (
        <div>
          <h4 className="font-semibold text-gray-900 mb-3 border-b pb-1">Entity Details</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {Object.entries(groupedEntities).map(([type, items]) => (
              <div key={type}>
                <h5 className="text-sm font-semibold text-gray-700 mb-2">{typeDisplayNames[type] || type}</h5>
                <ul className="text-sm space-y-1">
                  {items.map((e, idx) => (
                    <li key={idx} className="text-gray-600 truncate bg-gray-50 px-2 py-1 rounded border border-gray-100" title={e.value}>
                      {e.value}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}
    </SectionCard>
  );
}
