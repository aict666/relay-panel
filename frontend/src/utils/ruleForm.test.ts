import { describe, expect, it } from 'vitest';
import { hasForwardFormError, ruleFormTabForErrors } from './ruleForm';

describe('hasForwardFormError', () => {
  it.each(['targets', 'max_connections', 'auto_restart_minutes'])(
    'routes %s validation failures to the Forward tab',
    (field) => {
      expect(hasForwardFormError([{ name: [field] }])).toBe(true);
    },
  );

  it('keeps basic-field validation failures on the Basic tab', () => {
    const errors = [
      { name: ['name'] },
      { name: ['device_group_in'] },
    ];
    expect(hasForwardFormError(errors)).toBe(false);
    expect(ruleFormTabForErrors(errors)).toBe('basic');
  });

  it('selects the Forward tab when any forward-field validation fails', () => {
    expect(ruleFormTabForErrors([
      { name: ['name'] },
      { name: ['targets', 0, 'host'] },
    ])).toBe('forward');
  });
});
