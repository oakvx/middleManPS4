"""Offline PSN metadata triage. No network access, no authentication contents."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import sys

from .psn_netdiag import DiagnosticError, comparison, load_summary


def triage(baseline: dict, attempt: dict) -> dict:
    diff = comparison(baseline, attempt)
    form = baseline['format']
    if form == 'fwSpoofer-netmeta-v1':
        observed = sum(attempt.get('counts', {}).get(k, 0) for k in
                       ('dns', 'tls_clienthello', 'tcp_syn', 'tcp_rst', 'tls_alert'))
        baseline_observed = sum(baseline.get('counts', {}).get(k, 0) for k in
                                ('dns', 'tls_clienthello', 'tcp_syn', 'tcp_rst', 'tls_alert'))
        new_destinations = {key: diff.get(key, []) for key in
                            ('dns_names_new', 'tls_sni_new', 'public_ips_new')}
    else:
        observed = attempt.get('counts', {}).get('connect_attempts', 0)
        baseline_observed = baseline.get('counts', {}).get('connect_attempts', 0)
        new_destinations = {'connect_hosts_new': diff['connect_hosts_new']}
    if not isinstance(observed, int) or not isinstance(baseline_observed, int):
        raise DiagnosticError('Contatori non validi')
    return {
        'format': 'fwSpoofer-psn-triage-v1',
        'ps4_ip': str(ipaddress.ip_address(diff['ps4_ip'])),
        'baseline_events': baseline_observed,
        'attempt_events': observed,
        'new_destinations': new_destinations,
        'interpretation': ('Nessun evento osservato durante il tentativo: visibilita della cattura non dimostrata; '
                           'NON prova un controllo locale.' if observed == 0 else
                           'Eventi di rete osservati: non determinano contenuto TLS, esito PSN, '
                           'origine del controllo firmware o possibilita di spoofing.'),
        'restrictions': ('Non includere credenziali, token o contenuti TLS. '
                         'Nessuna modifica al traffico o all autenticazione.'),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Confronto offline metadati PS4, senza rete')
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--attempt', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = triage(load_summary(args.baseline), load_summary(args.attempt))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (DiagnosticError, OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        print(f'ERRORE: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
