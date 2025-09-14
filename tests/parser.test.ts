import { describe, it, expect } from 'vitest';
import { parse } from '../src/parser';

describe('Parsing Auth Header field-value', () => {
  it('Should handle valid single space separated values', () => {
    const res = parse('BEARER VALUE');
    expect(res).toEqual({ scheme: 'BEARER', value: 'VALUE' });
  });

  it('Should reject non-bearer space separated values', () => {
    const res = parse('BASIC VALUE');
    expect(res).toBeNull();
  });

  it('Should accept Bearer with different casing', () => {
    const res = parse('Bearer VALUE');
    expect(res).toEqual({ scheme: 'Bearer', value: 'VALUE' });
  });

  it('Should reject CRLF separator', () => {
    const res = parse('BEARER\nVALUE');
    expect(res).toBeNull();
  });

  it('Should handle malformed authentication headers with no scheme', () => {
    const res = parse('malformed');
    expect(res).toBeNull();
  });

  it('Should return null when the auth header is not a string', () => {
    const res = parse({} as any);
    expect(res).toBeNull();
  });

  it('Should return null for empty string', () => {
    const res = parse('');
    expect(res).toBeNull();
  });

  it('Should return null for header with only scheme', () => {
    const res = parse('Bearer');
    expect(res).toBeNull();
  });

  it('Should return null for header with extra spaces', () => {
    const res = parse('Bearer  VALUE  EXTRA');
    expect(res).toBeNull();
  });
});