import React from 'react';
import {act, create, type ReactTestRenderer} from 'react-test-renderer';
import {TextInput} from 'react-native';
import ChatScreen from '../src/screens/ChatScreen';

const mockSend = jest.fn();
const mockRead = jest.fn(() => 'synthetic native history');
const mockApp: any = {
  session: {userId: 'synthetic-self', deviceId: 'synthetic-device', serverUrl: 'https://synthetic.invalid', publicKey: [], ed25519Pk: []},
  contacts: [], foreground: true, relayBatch: null, clearUnread: jest.fn(),
};
jest.mock('../src/lib/AppContext', () => ({useApp: () => mockApp, conversationIdFor: () => 'dm:synthetic'}));
jest.mock('../src/lib/core', () => ({getCore: () => ({sendText: mockSend, readMessage: mockRead, getLocalMessages: () => []})}));
jest.mock('react-native-liteseal', () => ({FfiRelayEvent_Tags: {Delivered: 0, Offline: 1, DeliveryUpdate: 2, Error: 3}}));
jest.mock('../src/components/Avatar', () => () => null);
jest.mock('../src/components/TrustLabel', () => () => null);

function contact() {
  return {userId: 'synthetic-peer', username: 'Synthetic', publicKey: new ArrayBuffer(32), ed25519Pk: new ArrayBuffer(32), fingerprint: 'synthetic-pin', keyChanged: false, trustState: 'verified'};
}
const props = {route: {params: {peerId: 'synthetic-peer'}}, navigation: {goBack: jest.fn(), navigate: jest.fn()}} as any;
let view: ReactTestRenderer;
beforeEach(() => {
  mockApp.foreground = true;
  mockApp.contacts = [contact()];
  mockSend.mockReset();
});
afterEach(async () => { if (view) await act(async () => view.unmount()); });

async function startPending() {
  const before = mockSend.mock.calls.length;
  let complete!: (id: string) => void;
  let fail!: (error: Error) => void;
  mockSend.mockImplementation(() => new Promise<string>((resolve, reject) => { complete = resolve; fail = reject; }));
  await act(async () => {
    if (view) view.unmount();
    view = create(<ChatScreen {...props} />);
  });
  await act(async () => view.root.findByType(TextInput).props.onChangeText('synthetic pending plaintext'));
  await act(async () => {
    const send = view.root.findByProps({accessibilityLabel: '发送消息'});
    void send.props.onPress();
  });
  expect(mockSend).toHaveBeenCalledTimes(before + 1);
  return {complete, fail};
}

test('late send success cannot restore body after background or foreground resume', async () => {
  const pending = await startPending();
  mockApp.foreground = false;
  await act(async () => view.update(<ChatScreen {...props} />));
  await act(async () => pending.complete('synthetic-old-message'));
  expect(JSON.stringify(view.toJSON())).not.toContain('synthetic pending plaintext');
  mockApp.foreground = true;
  await act(async () => view.update(<ChatScreen {...props} />));
  expect(JSON.stringify(view.toJSON())).not.toContain('synthetic pending plaintext');
});

test.each(['pin', 'peer', 'identity'])('late response cannot cross a changed %s', async change => {
  const pending = await startPending();
  if (change === 'pin') mockApp.contacts = [{...contact(), keyChanged: true}];
  if (change === 'identity') mockApp.session = {...mockApp.session, deviceId: 'synthetic-other-device'};
  const nextProps = change === 'peer' ? {...props, route: {params: {peerId: 'synthetic-other-peer'}}} : props;
  await act(async () => view.update(<ChatScreen {...nextProps} />));
  await act(async () => pending.complete('synthetic-old-message'));
  expect(JSON.stringify(view.toJSON())).not.toContain('synthetic pending plaintext');
  expect(JSON.stringify(view.toJSON())).not.toContain('synthetic-old-message');
});

test('late send failure is retired and current failure does not expose native error text', async () => {
  const retired = await startPending();
  mockApp.foreground = false;
  await act(async () => view.update(<ChatScreen {...props} />));
  await act(async () => retired.fail(new Error('synthetic sensitive transport detail')));
  expect(JSON.stringify(view.toJSON())).not.toContain('synthetic sensitive transport detail');
  mockApp.foreground = true;
  await act(async () => view.update(<ChatScreen {...props} />));
  const current = await startPending();
  await act(async () => current.fail(new Error('synthetic sensitive transport detail')));
  expect(JSON.stringify(view.toJSON())).toContain('发送未确认');
  expect(JSON.stringify(view.toJSON())).not.toContain('synthetic sensitive transport detail');
});
