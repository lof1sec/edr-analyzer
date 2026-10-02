import React from 'react';

/**
 * Consistent placeholder for empty lists/panels and "nothing here" states.
 */
export default function EmptyState({ icon: Icon, title, description, action, className = '' }) {
  return (
    <div className={`flex flex-col items-center justify-center text-center px-6 py-8 ${className}`}>
      {Icon && <Icon size={30} className="mb-3 text-slate-300 dark:text-slate-600" aria-hidden="true" />}
      <p className="text-sm font-semibold text-slate-600 dark:text-slate-300">{title}</p>
      {description && (
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 max-w-xs">{description}</p>
      )}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}
