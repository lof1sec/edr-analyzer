import assert from 'node:assert/strict';
import test from 'node:test';
import { createUploadForm } from '../src/utils/uploadForm.js';

test('CSV upload includes the file and selected timezone', () => {
  const file = new Blob(['ActionType,Timestamp\n'], { type: 'text/csv' });
  const form = createUploadForm(file, 'America/Santiago');
  assert.equal(form.get('timezone'), 'America/Santiago');
  assert.equal(form.get('file').size, file.size);
  assert.deepEqual([...form.keys()], ['file', 'timezone']);
});
