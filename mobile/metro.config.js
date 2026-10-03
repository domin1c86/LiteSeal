const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const path = require('node:path');
const config = {
  // The body codec is pure TypeScript and shared with Windows. Keep React and
  // React Native resolved from the mobile dependency tree.
  watchFolders: [path.resolve(__dirname, '../ui/src/lib')],
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
