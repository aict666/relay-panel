import { useCallback, useEffect, useRef } from 'react';

/**
 * Starts a request generation and returns a predicate that remains true only
 * while that generation is still the newest request owned by this component.
 *
 * Filters and pagination can start a second request before the first settles;
 * the older response must not overwrite the state the user selected later.
 */
export function useLatestRequestGuard() {
  const generation = useRef(0);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);

  return useCallback(() => {
    const current = ++generation.current;
    return () => mounted.current && generation.current === current;
  }, []);
}
