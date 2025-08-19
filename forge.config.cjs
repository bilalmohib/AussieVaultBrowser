const { FusesPlugin } = require("@electron-forge/plugin-fuses");
const { FuseV1Options, FuseVersion } = require("@electron/fuses");

module.exports = {
  packagerConfig: {
    asar: true,
    name: "Aussie Vault Browser",
    appBundleId: "com.aussievault.browser",
    executableName: "Aussie Vault Browser",
    icon: "build/icon", // This will automatically pick .icns for macOS, .ico for Windows, .png for Linux
    // Support multiple architectures
    osxUniversal: {
      mergeASARs: false,
    },
    // Disable code signing for now (enable for production with Apple Developer ID)
    osxSign: false,
    osxNotarize: false,
    // Additional options for builds
    ignore: [/\.DS_Store$/, /node_modules/],
  },
  rebuildConfig: {},
  makers: [
    {
      name: "@electron-forge/maker-squirrel",
      config: {
        name: "aussie_vault_browser",
        authors: "Versatile Technologies",
        description:
          "Aussie Vault Browser with VPN capabilities and 1Password integration",
      },
    },
    {
      name: "@electron-forge/maker-zip",
      platforms: ["darwin"],
      config: {
        name: "AussieVaultBrowser-{{version}}-{{arch}}.zip",
      },
    },
    {
      name: "@electron-forge/maker-dmg",
      config: {},
    },
    {
      name: "@electron-forge/maker-deb",
      config: {},
    },
    {
      name: "@electron-forge/maker-rpm",
      config: {},
    },
  ],
  publishers: [
    {
      name: "@electron-forge/publisher-github",
      config: {
        repository: {
          owner: "bilalmohib",
          name: "AussieVaultBrowser",
        },
        prerelease: false,
        draft: false,
        generateReleaseNotes: true,
        tagPrefix: "v",
      },
    },
  ],
  plugins: [
    {
      name: "@electron-forge/plugin-auto-unpack-natives",
      config: {},
    },
    new FusesPlugin({
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
    }),
  ],
};
