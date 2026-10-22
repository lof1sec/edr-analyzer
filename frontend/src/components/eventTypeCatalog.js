export function mergeEventTypeSelection(previous, catalog) {
  return {
    ...previous,
    ...Object.fromEntries(catalog.map(type => [type, previous[type] !== false])),
  };
}

export function setCatalogEventTypes(previous, catalog, checked) {
  return { ...previous, ...Object.fromEntries(catalog.map(type => [type, checked])) };
}
