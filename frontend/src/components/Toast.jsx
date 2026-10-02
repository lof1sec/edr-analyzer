import React, { useCallback, useMemo, useState } from 'react';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';
import { ToastContext } from '../hooks/useToast';

let nextToastId = 1;

const VARIANTS = {
  success: {
    Icon: CheckCircle2,
    iconClass: 'text-green-500',
    border: 'border-green-200 dark:border-green-800',
  },
  error: {
    Icon: AlertCircle,
    iconClass: 'text-red-500',
    border: 'border-red-200 dark:border-red-800',
  },
  info: {
    Icon: Info,
    iconClass: 'text-blue-500',
    border: 'border-slate-200 dark:border-slate-700',
  },
};

/**
 * App-wide toast notifications. Wrap the app once and call `useToast()` to
 * surface transient success/error feedback instead of inline text or `alert()`.
 */
export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const dismiss = useCallback((id) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const notify = useCallback(
    (message, type = 'info', duration = 4000) => {
      const id = nextToastId++;
      setToasts((current) => [...current, { id, message, type }]);
      if (duration > 0) {
        setTimeout(() => dismiss(id), duration);
      }
      return id;
    },
    [dismiss],
  );

  const value = useMemo(
    () => ({
      notify,
      success: (message, duration) => notify(message, 'success', duration),
      error: (message, duration) => notify(message, 'error', duration),
      info: (message, duration) => notify(message, 'info', duration),
    }),
    [notify],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-72 max-w-[calc(100vw-2rem)]"
        aria-live="polite"
        aria-atomic="false"
      >
        {toasts.map(({ id, message, type }) => {
          const { Icon, iconClass, border } = VARIANTS[type] || VARIANTS.info;
          return (
            <div
              key={id}
              role="status"
              className={`flex items-start gap-2 rounded-lg border px-3 py-2 shadow-lg text-xs bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 ${border}`}
            >
              <Icon size={16} className={`mt-0.5 shrink-0 ${iconClass}`} aria-hidden="true" />
              <span className="flex-1 break-words">{message}</span>
              <button
                onClick={() => dismiss(id)}
                className="shrink-0 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors"
                aria-label="Dismiss notification"
                title="Dismiss"
              >
                <X size={14} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
