import { describe, expect, it } from 'vitest';
import { buildInstallCommand, shellQuote } from './installCommand';

describe('installation command escaping', () => {
  it('single-quotes ordinary arguments', () => {
    expect(shellQuote('https://panel.example/path?a=1&b=2'))
      .toBe("'https://panel.example/path?a=1&b=2'");
  });

  it('escapes embedded single quotes without ending the argument', () => {
    expect(shellQuote("a'b")).toBe("'a'\"'\"'b'");
  });

  it('quotes every externally supplied command argument', () => {
    expect(buildInstallCommand('https://scripts.example/i.sh', 'tok; touch /tmp/pwned', 'https://panel/?x=$(id)'))
      .toBe("bash <(curl -fsSL 'https://scripts.example/i.sh') -t 'tok; touch /tmp/pwned' -u 'https://panel/?x=$(id)'");
  });
});
