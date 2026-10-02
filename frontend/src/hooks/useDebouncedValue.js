import { useEffect, useState } from 'react';

/**
 * Return a value that only updates once `value` has stopped changing for
 * `delay` milliseconds. Used to avoid re-running expensive filters on every
 * keystroke.
 */
export function useDebouncedValue(value, delay = 250) {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const timeoutId = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timeoutId);
  }, [value, delay]);

  return debouncedValue;
}
