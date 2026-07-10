import React from 'react';
import { Text, View } from 'react-native';
import { fonts, radius, useTheme } from '../theme';

// Square hairline avatar with mono initials, matching the desktop look.
export default function Avatar({ name, size = 42 }: { name: string; size?: number }) {
  const { colors } = useTheme();
  const initials = name.trim().slice(0, 2).toUpperCase() || '?';
  return (
    <View
      style={{
        width: size,
        height: size,
        borderRadius: radius.sm,
        borderWidth: 1,
        borderColor: colors.borderStrong,
        backgroundColor: colors.surfaceMuted,
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Text
        style={{
          fontFamily: fonts.mono,
          fontSize: size / 3,
          color: colors.textMuted,
        }}
      >
        {initials}
      </Text>
    </View>
  );
}
