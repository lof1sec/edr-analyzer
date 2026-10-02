import { createContext, useContext } from 'react';

export const ToastContext = createContext(null);

/**
 * Access the app-wide toast API. Must be used under <ToastProvider>.
 */
export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
