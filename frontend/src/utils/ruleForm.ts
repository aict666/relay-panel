export interface RuleFormErrorField {
  name: (string | number)[];
}

export type RuleFormTab = 'basic' | 'forward';

const FORWARD_TAB_FIELDS = new Set([
  'targets',
  'max_connections',
  'auto_restart_minutes',
]);

/** Whether a validation failure belongs to the rule form's Forward tab. */
export function hasForwardFormError(errorFields: RuleFormErrorField[]): boolean {
  return errorFields.some(({ name }) => FORWARD_TAB_FIELDS.has(String(name[0])));
}

/** Select the tab that contains the validation error the user needs to fix. */
export function ruleFormTabForErrors(errorFields: RuleFormErrorField[]): RuleFormTab {
  return hasForwardFormError(errorFields) ? 'forward' : 'basic';
}
