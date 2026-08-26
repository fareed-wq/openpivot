import React from 'react';

export default function SectionNav({ type, collectors, correlation }) {
  const handleScroll = (e, id) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      window.dispatchEvent(new Event(`expand-section-${id}`));
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const navItems = [];
  if (type === 'domain') {
    navItems.push({ id: 'sec-overview', label: 'Overview' });
    if (collectors?.dns) navItems.push({ id: 'sec-dns', label: 'DNS' });
    if (collectors?.email_security) navItems.push({ id: 'sec-email', label: 'Email' });
    if (collectors?.rdap) navItems.push({ id: 'sec-rdap', label: 'RDAP' });
    if (collectors?.tls) navItems.push({ id: 'sec-tls', label: 'TLS' });
    if (collectors?.http_metadata) navItems.push({ id: 'sec-http', label: 'HTTP' });
  } else if (type === 'ipv4') {
    navItems.push({ id: 'sec-overview', label: 'Overview' });
    if (collectors?.ip) {
      navItems.push({ id: 'sec-rdap', label: 'RDAP' });
      navItems.push({ id: 'sec-reversedns', label: 'Reverse DNS' });
    }
    if (collectors?.asn) navItems.push({ id: 'sec-asn', label: 'ASN' });
  }

  if (correlation && (correlation.entities?.length > 0 || correlation.relationships?.length > 0)) {
    navItems.push({ id: 'sec-infra', label: 'Infrastructure' });
  }

  if (navItems.length === 0) return null;

  return (
    <div className="sticky top-0 z-10 bg-white/95 backdrop-blur shadow-sm border-b border-gray-200 py-3 px-4 -mx-4 sm:mx-0 sm:rounded-lg sm:border-x mb-6 flex overflow-x-auto whitespace-nowrap gap-2 items-center hide-scrollbar">
      <span className="text-gray-500 font-medium text-sm mr-2">Jump to:</span>
      {navItems.map((item, idx) => (
        <a
          key={item.id}
          href={`#${item.id}`}
          onClick={(e) => handleScroll(e, item.id)}
          className="text-sm font-semibold text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-full transition-colors flex-shrink-0"
        >
          {item.label}
        </a>
      ))}
    </div>
  );
}
