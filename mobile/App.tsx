import React, { useEffect, useState } from 'react';
import { StatusBar, Text, View } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import {
  DarkTheme,
  DefaultTheme,
  NavigationContainer,
} from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { AppProvider, useApp } from './src/lib/AppContext';
import { getCore } from './src/lib/core';
import { publicSession } from './src/lib/keystore';
import { fonts, useTheme } from './src/theme';
import type { RootStackParamList, TabParamList } from './src/navigation';
import LoginScreen from './src/screens/LoginScreen';
import ChatsScreen from './src/screens/ChatsScreen';
import ChatScreen from './src/screens/ChatScreen';
import ContactsScreen from './src/screens/ContactsScreen';
import ContactDetailScreen from './src/screens/ContactDetailScreen';
import AddContactScreen from './src/screens/AddContactScreen';
import SettingsScreen from './src/screens/SettingsScreen';

const Stack = createNativeStackNavigator<RootStackParamList>();
const Tab = createBottomTabNavigator<TabParamList>();

function Tabs() {
  const { colors } = useTheme();
  const { unread } = useApp();
  const totalUnread = Object.values(unread).reduce((a, b) => a + b, 0);

  return (
    <Tab.Navigator
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: colors.sidebarBg,
          borderTopColor: colors.border,
          height: 56,
        },
        tabBarActiveTintColor: colors.text,
        tabBarInactiveTintColor: colors.textSubtle,
        tabBarLabelStyle: { fontFamily: fonts.mono, fontSize: 10.5 },
      }}
    >
      <Tab.Screen
        name="ChatsTab"
        component={ChatsScreen}
        options={{
          tabBarLabel: 'chats',
          tabBarBadge: totalUnread > 0 ? totalUnread : undefined,
          tabBarBadgeStyle: {
            backgroundColor: colors.accent,
            color: colors.accentContrast,
            fontSize: 10,
          },
          tabBarIcon: ({ color }) => <TabGlyph glyph="▤" color={color} />,
        }}
      />
      <Tab.Screen
        name="ContactsTab"
        component={ContactsScreen}
        options={{
          tabBarLabel: 'contacts',
          tabBarIcon: ({ color }) => <TabGlyph glyph="◫" color={color} />,
        }}
      />
      <Tab.Screen
        name="SettingsTab"
        component={SettingsScreen}
        options={{
          tabBarLabel: 'settings',
          tabBarIcon: ({ color }) => <TabGlyph glyph="⚙" color={color} />,
        }}
      />
    </Tab.Navigator>
  );
}

function TabGlyph({ glyph, color }: { glyph: string; color: string }) {
  return <Text style={{ fontSize: 15, color }}>{glyph}</Text>;
}

function Root() {
  const { colors, dark } = useTheme();
  const { session, setSession, setConnected } = useApp();
  const [loading, setLoading] = useState(true);

  // The native core owns identity, credentials, migration and token refresh.
  useEffect(() => {
    let retired=false;
    void (async()=>{
      try {
        const identity=await getCore().restoreIdentity();
        if(retired || !identity?.hasSession) return;
        let connected=false;
        try {await getCore().resumeNative();connected=true;}catch{}
        if(!retired){setConnected(connected);setSession(publicSession(identity,connected));}
      } catch { /* Preserve damaged or unavailable native data; do not replace keys. */ }
      finally {if(!retired)setLoading(false);}
    })();
    return()=>{retired=true;};
  },[setConnected,setSession]);
  const navTheme = {
    ...(dark ? DarkTheme : DefaultTheme),
    colors: {
      ...(dark ? DarkTheme : DefaultTheme).colors,
      background: colors.workspaceBg,
      card: colors.sidebarBg,
      border: colors.border,
      text: colors.text,
      primary: colors.accent,
    },
  };

  if (loading) {
    return (
      <View
        style={{
          flex: 1,
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: colors.workspaceBg,
        }}
      >
        <Text
          style={{
            fontFamily: fonts.mono,
            fontSize: 18,
            fontWeight: '600',
            color: colors.textMuted,
          }}
        >
          liteseal
          <Text style={{ color: colors.textSubtle, fontWeight: '400' }}>▌</Text>
        </Text>
      </View>
    );
  }

  return (
    <NavigationContainer theme={navTheme}>
      <StatusBar
        barStyle={dark ? 'light-content' : 'dark-content'}
        backgroundColor={colors.workspaceBg}
      />
      {session ? (
        <Stack.Navigator screenOptions={{ headerShown: false }}>
          <Stack.Screen name="Tabs" component={Tabs} />
          <Stack.Screen name="Chat" component={ChatScreen} />
          <Stack.Screen name="ContactDetail" component={ContactDetailScreen} />
          <Stack.Screen
            name="AddContact"
            component={AddContactScreen}
            options={{ presentation: 'modal', animation: 'slide_from_bottom' }}
          />
        </Stack.Navigator>
      ) : (
        <LoginScreen />
      )}
    </NavigationContainer>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <AppProvider>
        <Root />
      </AppProvider>
    </SafeAreaProvider>
  );
}
