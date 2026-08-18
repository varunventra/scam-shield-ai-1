/**
 * Single source of truth for scam-type labels and colors.
 *
 * Previously duplicated (with drifting casing) across OverviewPage,
 * FindingsPage, ReportsPage, and DemoPage.
 */

// Human-readable scam-type labels. Keys are backend enum values, lowercased.
export const TYPE_LABELS = {
  sbi_bank_fraud:     'SBI Bank Fraud',
  kyc_expiry:         'KYC Expiry',
  job_offer:          'Job Offer',
  lottery:            'Lottery',
  delivery:           'Delivery',
  investment_scam:    'Investment Scam',
  police_threat:      'Police Threat',
  bank_fraud:         'Bank Fraud',
  upi_fraud:          'UPI Fraud',
  phishing:           'Phishing',
  generic_fraud:      'Generic Fraud',
  manual:             'Manual',
  otp_fraud:          'OTP Fraud',
  bank_impersonation: 'Bank Impersonation',
  job_scam:           'Job Offer Scam',
  lottery_scam:       'Lottery Scam',
  delivery_scam:      'Delivery Scam',
  digital_arrest:     'Digital Arrest',
  utility_scam:       'Utility Scam',
  unknown:            'Unknown',
}

/** Format a scam-type key to a display label, falling back to Title Case. */
export function formatScamType(key) {
  if (!key) return 'Unknown'
  return TYPE_LABELS[key] || key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

// Distinct muted color per scam type — used for left border, chart slices, and Reports tab.
export const SCAM_COLORS = {
  upi_fraud:          '#4f46e5',  // indigo
  bank_impersonation: '#2563eb',  // blue
  otp_fraud:          '#7c3aed',  // purple
  sbi_bank_fraud:     '#2563eb',  // blue
  kyc_expiry:         '#7c3aed',  // purple
  bank_fraud:         '#2563eb',  // blue
  lottery_scam:       '#b45309',  // amber
  lottery:            '#b45309',
  job_scam:           '#0f766e',  // teal
  job_offer:          '#0f766e',
  delivery_scam:      '#0369a1',  // sky
  delivery:           '#0369a1',
  investment_scam:    '#4d7c0f',  // lime
  police_threat:      '#9f1239',  // rose
  digital_arrest:     '#9f1239',  // rose
  utility_scam:       '#a16207',  // yellow-brown
  phishing:           '#6d28d9',  // violet
  generic_fraud:      '#52525b',  // zinc
  unknown:            '#52525b',
  manual:             '#3f3f46',
}
