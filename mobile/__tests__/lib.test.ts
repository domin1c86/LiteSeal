import { dmConversationId } from '../src/lib/conversation';
import {
  bufferToBytes,
  bytesToBuffer,
  groupFingerprint,
  utf8Decode,
  utf8Encode,
} from '../src/lib/bytes';

test('dm conversation id is order independent', () => {
  expect(dmConversationId('alice', 'bob')).toBe('dm:alice:bob');
  expect(dmConversationId('bob', 'alice')).toBe('dm:alice:bob');
});

test('utf8 round-trips ascii and multibyte text', () => {
  for (const text of ['hello', '你好，轻密', 'emoji 🔐 test', '']) {
    expect(utf8Decode(utf8Encode(text))).toBe(text);
  }
});

test('buffer conversion round-trips byte arrays', () => {
  const bytes = [0, 1, 127, 128, 255];
  expect(bufferToBytes(bytesToBuffer(bytes))).toEqual(bytes);
});

test('fingerprint grouping splits into blocks of four', () => {
  expect(groupFingerprint('a3f109bc44d2e871')).toBe('a3f1 09bc 44d2 e871');
});
