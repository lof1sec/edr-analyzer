export function createUploadForm(file, timezone) {
  const form = new FormData();
  form.append('file', file);
  form.append('timezone', timezone);
  return form;
}
