// SENTINEL — Compliance citation map (JS mirror of sentinel/compliance/mappings.yaml).
// Keep in lock-step with mappings.yaml. The data is hand-curated, so a
// drift between the two is reviewable.
//
// Shape:
//   COMPLIANCE[agentId] = [{framework, reference, note}, ...]

export const COMPLIANCE = {
  A_004: [
    { framework: 'PCI-DSS', reference: '3.4',
      note: 'Cardholder data must not be stored in cleartext.' },
    { framework: 'PCI-DSS', reference: '3.5.1',
      note: 'Cryptographic keys must be protected against disclosure.' },
    { framework: 'GDPR',    reference: 'Art. 32(1)(a)',
      note: 'Encryption keys must be protected as part of technical measures.' },
    { framework: 'HIPAA',   reference: '164.312(a)(2)(iv)',
      note: 'Encryption and decryption keys must be safeguarded.' },
  ],
  C_005: [
    { framework: 'PCI-DSS', reference: '3.5.1' },
    { framework: 'GDPR',    reference: 'Art. 32(1)(a)' },
  ],
  C_017: [
    { framework: 'PCI-DSS', reference: '3.5.1' },
    { framework: 'PCI-DSS', reference: '4.2',
      note: 'Strong cryptography during transmission depends on key secrecy.' },
  ],
  N_001: [
    { framework: 'PCI-DSS', reference: '4.1',
      note: 'Strong cryptography during transmission over open networks.' },
    { framework: 'HIPAA',   reference: '164.312(e)(1)',
      note: 'Technical security measures for ePHI in transit.' },
    { framework: 'GDPR',    reference: 'Art. 32(1)(a)' },
  ],
  N_008: [
    { framework: 'PCI-DSS', reference: '4.1.1' },
    { framework: 'HIPAA',   reference: '164.312(e)(2)(ii)' },
  ],
  I_001: [
    { framework: 'GDPR',    reference: 'Art. 32(1)(b)',
      note: 'Ensure ongoing confidentiality and integrity of processing systems.' },
    { framework: 'HIPAA',   reference: '164.312(a)(1)',
      note: 'Access controls restrict to authorized users.' },
  ],
  B_008: [
    { framework: 'PCI-DSS', reference: '7.1',
      note: 'Restrict access on a need-to-know basis — client-side enforcement is not sufficient.' },
  ],
  PRIV_001: [
    { framework: 'GDPR',    reference: 'Art. 6(1)(a)',
      note: 'Lawful basis: explicit consent must precede collection.' },
    { framework: 'GDPR',    reference: 'Art. 7',
      note: 'Conditions for consent.' },
    { framework: 'GDPR',    reference: 'Art. 5(1)(c)',
      note: 'Data minimisation.' },
    { framework: 'DPDP',    reference: '6(1)',
      note: 'Consent must be free, specific, informed and unambiguous.' },
    { framework: 'CCPA',    reference: '1798.100(b)' },
  ],
  SCA_002: [
    { framework: 'GDPR',    reference: 'Art. 28',
      note: 'Processor obligations: third-party SDKs act as processors.' },
    { framework: 'GDPR',    reference: 'Art. 5(1)(c)',
      note: 'Data minimisation — SDK permission scope must match purpose.' },
  ],
  C_006: [
    { framework: 'PCI-DSS', reference: '3.4.1',
      note: 'Cryptographic primitives must be strong and used correctly.' },
    { framework: 'HIPAA',   reference: '164.312(a)(2)(iv)' },
  ],
  C_018: [
    { framework: 'PCI-DSS', reference: '3.4' },
    { framework: 'HIPAA',   reference: '164.312(e)(2)(ii)' },
    { framework: 'GDPR',    reference: 'Art. 32(1)(a)' },
  ],
  LOGIC_001: [
    { framework: 'PCI-DSS', reference: '6.4.4',
      note: 'Test data and accounts must be removed before production release.' },
    { framework: 'GDPR',    reference: 'Art. 32(1)(b)' },
  ],
  RES_002: [
    { framework: 'PCI-DSS', reference: '10.6',
      note: 'Resource exhaustion masks attack.' },
    { framework: 'HIPAA',   reference: '164.308(a)(1)(ii)(B)',
      note: 'Risk management — availability of ePHI.' },
  ],
};

/** Return citations for an agent_id, or empty array. */
export function citationsFor(agentId) {
  if (!agentId) return [];
  return COMPLIANCE[agentId] || [];
}

/** True when the agent has any tracked citation. */
export function hasCompliance(agentId) {
  return Array.isArray(COMPLIANCE[agentId]) && COMPLIANCE[agentId].length > 0;
}
