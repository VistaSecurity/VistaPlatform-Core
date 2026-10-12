import { useEffect, useState } from 'react';

/** Default quiet period before a typed search reaches a query key. */
export const SEARCH_DEBOUNCE_MS = 250;

/**
 * `value`, but only after it has stopped changing for `delayMs`.
 *
 * Feed the RAW value to the input (so typing stays instant) and the DEBOUNCED
 * value to the query key (so a burst of keystrokes is one request).
 */
export function useDebouncedValue<T>(value: T, delayMs: number = SEARCH_DEBOUNCE_MS): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}
