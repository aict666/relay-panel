import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useLatestRequestGuard } from './useLatestRequestGuard';

describe('useLatestRequestGuard', () => {
  it('invalidates an older request when a newer one starts', () => {
    const { result } = renderHook(() => useLatestRequestGuard());
    let first!: () => boolean;
    let second!: () => boolean;

    act(() => {
      first = result.current();
      second = result.current();
    });

    expect(first()).toBe(false);
    expect(second()).toBe(true);
  });

  it('invalidates the active request after unmount', () => {
    const { result, unmount } = renderHook(() => useLatestRequestGuard());
    const active = result.current();
    expect(active()).toBe(true);

    unmount();

    expect(active()).toBe(false);
  });
});
