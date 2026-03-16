/**
 * Display formatting utilities for record values.
 */

export function formatFieldValue(value: unknown, type: string): string {
  if (value === null || value === undefined) return '\u2014';
  if (type === 'boolean') return value ? 'Yes' : 'No';
  if (type === 'datetime' && typeof value === 'string') {
    return value.replace('T', ' ').slice(0, 19);
  }
  return String(value);
}

export const STATUS_COLORS: Record<string, string> = {
  Published: 'badge-green',
  Active: 'badge-green',
  Delivered: 'badge-green',
  Shipped: 'badge-green',
  Draft: 'badge-yellow',
  Pending: 'badge-yellow',
  Processing: 'badge-yellow',
  Archived: 'badge-gray',
  Discontinued: 'badge-gray',
  Cancelled: 'badge-gray',
  'Out of Stock': 'badge-red',
};
