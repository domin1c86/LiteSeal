import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';
import type { FfiContact, FfiPollResult } from 'react-native-liteseal';
import { getCore } from './core';
import { dmConversationId } from './conversation';

export interface Session {
  userId: string;
  token: string;
  refreshToken: string;
  deviceId: string;
  serverUrl: string;
  publicKey: number[];
  secretKey: number[];
  ed25519Pk: number[];
  ed25519Sk: number[];
  /** False when the relay could not be reached (offline session). */
  connected: boolean;
}

export interface RelayBatch {
  seq: number;
  result: FfiPollResult;
}

interface AppContextValue {
  session: Session | null;
  setSession: (s: Session | null) => void;
  contacts: FfiContact[];
  refreshContacts: () => void;
  relayBatch: RelayBatch | null;
  /** Unread incoming-message count per canonical conversation id. */
  unread: Record<string, number>;
  clearUnread: (conversationId: string) => void;
  connected: boolean;
  setConnected: (c: boolean) => void;
}

const AppContext = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const value = useContext(AppContext);
  if (!value) {
    throw new Error('useApp must be used inside AppProvider');
  }
  return value;
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [contacts, setContacts] = useState<FfiContact[]>([]);
  const [relayBatch, setRelayBatch] = useState<RelayBatch | null>(null);
  const [unread, setUnread] = useState<Record<string, number>>({});
  const [connected, setConnected] = useState(false);
  const seqRef = useRef(0);

  const refreshContacts = useCallback(() => {
    if (!session) {
      return;
    }
    try {
      setContacts(getCore().getContacts());
    } catch (err) {
      console.error('Failed to load contacts:', err);
    }
  }, [session]);

  useEffect(() => {
    if (!session) {
      setContacts([]);
      setUnread({});
      setRelayBatch(null);
      return;
    }
    refreshContacts();
  }, [session, refreshContacts]);

  // Poll at the app level so incoming messages are acked and persisted even
  // when no conversation is open; screens consume batches for their
  // conversation — same structure as the desktop App.tsx loop.
  useEffect(() => {
    if (!session || !connected) {
      return;
    }
    const interval = setInterval(async () => {
      try {
        const result = await getCore().pollMessages();
        if (result.messages.length > 0 || result.events.length > 0) {
          seqRef.current += 1;
          setRelayBatch({ seq: seqRef.current, result });
          if (result.messages.length > 0) {
            setUnread(prev => {
              const next = { ...prev };
              for (const m of result.messages) {
                next[m.conversationId] = (next[m.conversationId] ?? 0) + 1;
              }
              return next;
            });
          }
        }
      } catch {
        // not connected; ignore
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [session, connected]);

  const clearUnread = useCallback((conversationId: string) => {
    setUnread(prev => {
      if (!prev[conversationId]) {
        return prev;
      }
      const next = { ...prev };
      delete next[conversationId];
      return next;
    });
  }, []);

  return (
    <AppContext.Provider
      value={{
        session,
        setSession,
        contacts,
        refreshContacts,
        relayBatch,
        unread,
        clearUnread,
        connected,
        setConnected,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function conversationIdFor(session: Session, peerUserId: string): string {
  return dmConversationId(session.userId, peerUserId);
}
