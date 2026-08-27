import re
import hashlib
from typing import Dict, List, Any, Optional
from app.models.correlation import Entity, Relationship, CorrelationResult

class CorrelationEngine:
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        # Used for org deduplication: map norm_name -> handle if available
        self.org_name_to_handle: Dict[str, str] = {}

    def _normalize_org_name(self, name: str) -> str:
        if not name:
            return ""
        name = name.strip().lower()
        name = re.sub(r'\s+', ' ', name)
        return name

    def add_entity(self, ent_id: str, ent_type: str, value: str, attributes: Optional[Dict[str, Any]] = None):
        if not attributes:
            attributes = {}
        if ent_id in self.entities:
            # Merge attributes deterministically
            for k, v in attributes.items():
                if k not in self.entities[ent_id].attributes or not self.entities[ent_id].attributes[k]:
                    self.entities[ent_id].attributes[k] = v
        else:
            self.entities[ent_id] = Entity(id=ent_id, type=ent_type, value=value, attributes=attributes)

    def add_relationship(self, source: str, target: str, rel_type: str, collector: str):
        rel_id = f"{source}|{rel_type}|{target}"
        if rel_id not in self.relationships:
            self.relationships[rel_id] = Relationship(
                source=source,
                target=target,
                type=rel_type,
                source_collectors=[collector]
            )
        else:
            if collector not in self.relationships[rel_id].source_collectors:
                self.relationships[rel_id].source_collectors.append(collector)

    def resolve_org_id(self, name: str, handle: str = None) -> Optional[str]:
        if not name and not handle:
            return None

        norm_name = self._normalize_org_name(name) if name else None

        # If handle provided, that's authoritative
        if handle:
            stable_handle = handle.strip().lower()
            if norm_name:
                self.org_name_to_handle[norm_name] = stable_handle
            return f"org:{stable_handle}"

        # If no handle but name exists
        if norm_name:
            if norm_name in self.org_name_to_handle:
                return f"org:{self.org_name_to_handle[norm_name]}"

            h = hashlib.sha256(norm_name.encode('utf-8')).hexdigest()[:16]
            return f"org:name:{h}"

        return None

    def build(self) -> CorrelationResult:
        # Sort entities by type, then id
        sorted_entities = sorted(self.entities.values(), key=lambda e: (e.type, e.id))

        # Sort relationships by source, type, target
        for rel in self.relationships.values():
            rel.source_collectors.sort()

        sorted_relationships = sorted(self.relationships.values(), key=lambda r: (r.source, r.type, r.target))

        return CorrelationResult(entities=sorted_entities, relationships=sorted_relationships)


def build_correlations(
    domain_result: dict = None,
    dns_result: dict = None,
    tls_result: dict = None,
    ct_result: dict = None,
    ip_result: dict = None,
    asn_result: dict = None
) -> dict:

    engine = CorrelationEngine()

    domain_id = None

    if dns_result and dns_result.get("status") == "success":
        domain = dns_result.get("domain")
        if domain:
            domain_id = f"domain:{domain.lower()}"
            engine.add_entity(domain_id, "domain", domain)

            records = dns_result.get("records", {})

            # A/AAAA -> IP
            for rec_type in ("A", "AAAA"):
                rec_data = records.get(rec_type)
                if rec_data and isinstance(rec_data, dict):
                    for ip in rec_data.get("values", []):
                        if ip:
                            ip_id = f"ip:{ip}"
                            engine.add_entity(ip_id, "ip", ip)
                            engine.add_relationship(domain_id, ip_id, "resolves_to", "dns")

            # NS -> nameserver
            ns_data = records.get("NS")
            if ns_data and isinstance(ns_data, dict):
                for ns in ns_data.get("values", []):
                    if ns:
                        ns = ns.lower().rstrip('.')
                        ns_id = f"ns:{ns}"
                        engine.add_entity(ns_id, "nameserver", ns)
                        engine.add_relationship(domain_id, ns_id, "uses_nameserver", "dns")

            # MX -> mail_server
            mx_data = records.get("MX")
            if mx_data and isinstance(mx_data, dict):
                for mx in mx_data.get("values", []):
                    if isinstance(mx, dict):
                        host = mx.get("host")
                    else:
                        host = mx
                    if host:
                        host = host.lower().rstrip('.')
                        mx_id = f"mx:{host}"
                        engine.add_entity(mx_id, "mail_server", host)
                        engine.add_relationship(domain_id, mx_id, "uses_mail_server", "dns")

    if tls_result and tls_result.get("status") == "success":
        domain = tls_result.get("domain")
        if domain:
            domain_id = f"domain:{domain.lower()}"
            engine.add_entity(domain_id, "domain", domain)

            cert = tls_result.get("certificate")
            if cert:
                fingerprint = cert.get("sha256_fingerprint")
                if fingerprint:
                    clean_fp = fingerprint.lower().replace(':', '')
                    cert_id = f"cert:{clean_fp}"

                    attrs = {}
                    if "subject" in cert and cert["subject"]: attrs["subject"] = cert["subject"]
                    if "issuer" in cert and cert["issuer"]: attrs["issuer"] = cert["issuer"]
                    if "not_before" in cert and cert["not_before"]: attrs["not_before"] = cert["not_before"]
                    if "not_after" in cert and cert["not_after"]: attrs["not_after"] = cert["not_after"]

                    engine.add_entity(cert_id, "certificate", clean_fp, attrs)
                    engine.add_relationship(domain_id, cert_id, "presents_certificate", "tls")

                    for san in cert.get("san_dns", []):
                        if san:
                            san = san.lower()
                            host_id = f"host:{san}"
                            engine.add_entity(host_id, "hostname", san)
                            engine.add_relationship(cert_id, host_id, "contains_hostname", "tls")


    if ct_result and ct_result.get("status") == "success" and domain_result:
        domain = domain_result.get("domain")
        if domain:
            domain_id = f"domain:{domain.lower()}"
            engine.add_entity(domain_id, "domain", domain)

            for hostname in ct_result.get("hostnames", []):
                host_id = f"domain:{hostname.lower()}"
                engine.add_entity(host_id, "domain", hostname)
                engine.add_relationship(domain_id, host_id, "ct_observed_hostname", "ct")

    if ip_result:
        ip = ip_result.get("ip")
        if ip:
            ip_id = f"ip:{ip}"

            attrs = {}
            rdap = ip_result.get("rdap")
            if rdap:
                if "network_prefixes" in rdap and rdap["network_prefixes"]:
                    attrs["prefixes"] = rdap["network_prefixes"]
                if "country" in rdap and rdap["country"]:
                    attrs["country"] = rdap["country"]
                if "name" in rdap and rdap["name"]:
                    attrs["network_name"] = rdap["name"]

            engine.add_entity(ip_id, "ip", ip, attributes=attrs)

            rev_dns = ip_result.get("reverse_dns")
            if rev_dns and rev_dns.get("status") == "success" and rev_dns.get("hostname"):
                hostname = rev_dns["hostname"].lower().rstrip('.')
                host_id = f"host:{hostname}"
                engine.add_entity(host_id, "hostname", hostname)
                engine.add_relationship(ip_id, host_id, "reverse_resolves_to", "reverse_dns")

            if rdap:
                org = rdap.get("organization")
                if org:
                    org_name = org.get("name")
                    org_handle = org.get("handle")
                    org_id = engine.resolve_org_id(org_name, org_handle)
                    if org_id:
                        engine.add_entity(org_id, "organization", org_name or org_handle)
                        engine.add_relationship(ip_id, org_id, "registered_to", "ip_rdap")

    if asn_result:
        origin = asn_result.get("origin")
        asn_rdap = asn_result.get("asn")

        if origin and origin.get("ip"):
            ip_id = f"ip:{origin['ip']}"
            engine.add_entity(ip_id, "ip", origin["ip"])

            for asn_val in origin.get("asns", []):
                asn_id = f"asn:{asn_val}"

                attrs = {}
                if origin.get("country"): attrs["country"] = origin["country"]
                if origin.get("registry"): attrs["registry"] = origin["registry"]

                engine.add_entity(asn_id, "asn", str(asn_val), attributes=attrs)
                engine.add_relationship(ip_id, asn_id, "announced_by", "asn")

        if asn_rdap and asn_rdap.get("number"):
            asn_val = asn_rdap["number"]
            asn_id = f"asn:{asn_val}"

            attrs = {}
            if asn_rdap.get("name"): attrs["name"] = asn_rdap["name"]
            if asn_rdap.get("country"): attrs["country"] = asn_rdap["country"]
            if asn_rdap.get("type"): attrs["type"] = asn_rdap["type"]

            engine.add_entity(asn_id, "asn", str(asn_val), attributes=attrs)

            org = asn_rdap.get("organization")
            if org:
                org_name = org.get("name")
                org_handle = org.get("handle")
                org_id = engine.resolve_org_id(org_name, org_handle)
                if org_id:
                    engine.add_entity(org_id, "organization", org_name or org_handle)
                    engine.add_relationship(asn_id, org_id, "registered_to", "asn")

    # Do a second pass to update any organization entities that might have been merged by name -> handle
    # in a later step.
    final_entities = {}
    fixed_relationships = {}

    def get_latest_org_id(old_id: str, value: str) -> str:
        if not old_id.startswith("org:name:"):
            return old_id
        norm_name = engine._normalize_org_name(value)
        if norm_name in engine.org_name_to_handle:
            return f"org:{engine.org_name_to_handle[norm_name]}"
        return old_id

    for ent_id, ent in engine.entities.items():
        if ent.type == "organization":
            new_id = get_latest_org_id(ent_id, ent.value)
            ent.id = new_id
            if new_id in final_entities:
                for k, v in ent.attributes.items():
                    if k not in final_entities[new_id].attributes or not final_entities[new_id].attributes[k]:
                        final_entities[new_id].attributes[k] = v
            else:
                final_entities[new_id] = ent
        else:
            final_entities[ent_id] = ent

    engine.entities = final_entities

    for rel_id, rel in engine.relationships.items():
        def _fix_id(old_id):
            if old_id.startswith("org:name:") and old_id in engine.entities:
                val = engine.entities[old_id].value
                return get_latest_org_id(old_id, val)
            return old_id

        new_source = _fix_id(rel.source)
        new_target = _fix_id(rel.target)

        new_rel_id = f"{new_source}|{rel.type}|{new_target}"
        if new_rel_id in fixed_relationships:
            for c in rel.source_collectors:
                if c not in fixed_relationships[new_rel_id].source_collectors:
                    fixed_relationships[new_rel_id].source_collectors.append(c)
        else:
            rel.source = new_source
            rel.target = new_target
            fixed_relationships[new_rel_id] = rel

    engine.relationships = fixed_relationships

    return engine.build().model_dump()
