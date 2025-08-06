# Google OAuth Security Configuration for Production

## Issue: "Couldn't sign you in - This browser or app may not be secure"

Google's OAuth system treats Electron apps as potentially insecure unless they meet specific security requirements. Here's how to make your app secure for production:

## ✅ Implemented Security Enhancements

### 1. **Enhanced User-Agent**

- Updated to latest Chrome User-Agent with Edge compatibility
- Added app identifier for transparency
- Makes Google recognize the app as a legitimate browser

### 2. **Security Headers Configuration**

- Content Security Policy (CSP) with Google OAuth domains whitelisted
- X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
- Referrer Policy and Permissions Policy configured

### 3. **Session Security**

- Enhanced permission handling for OAuth flows
- Secure cookie configuration with persistent storage
- Mixed content protection (blocks HTTP on HTTPS)

### 4. **Code Signing Configuration** (Production Ready)

- macOS: Apple Developer ID signing with hardened runtime
- Windows: Code signing metadata configured
- Notarization support for macOS apps

## 🚀 Steps to Enable for Production

### 1. **Code Signing** (MOST IMPORTANT)

#### For macOS:

```bash
# Set environment variables
export APPLE_DEVELOPER_ID="Developer ID Application: Your Name (TEAM_ID)"
export APPLE_ID="your-apple-id@email.com"
export APPLE_ID_PASSWORD="app-specific-password"
export APPLE_TEAM_ID="YOUR_TEAM_ID"
export NODE_ENV="production"

# Build with signing
npm run make:mac
```

#### For Windows:

```bash
# Install signing certificate and set environment
# Then build
npm run make:win
```

### 2. **Google OAuth App Configuration**

In your Google Cloud Console:

1. **Application Type**: Set to "Desktop application"
2. **Bundle ID**: Use `com.aussievault.browser` (matches your app)
3. **Authorized Redirect URIs**:
   - `aussievault://oauth/callback`
   - `http://localhost:3000/auth/callback` (for development)

### 3. **App Store Distribution** (Recommended)

#### macOS App Store:

- Enables automatic code signing
- Provides highest security trust level
- Google recognizes App Store apps as secure

#### Microsoft Store:

- Similar benefits for Windows
- Automatic signing and validation

### 4. **Alternative: Self-Signing for Testing**

For immediate testing without certificates:

```bash
# Create self-signed certificate (Windows)
New-SelfSignedCertificate -DnsName "AussieVaultBrowser" -Type CodeSigning -CertStoreLocation Cert:\CurrentUser\My

# Sign the executable
signtool sign /s MY /n "AussieVaultBrowser" "path\to\your\app.exe"
```

## 🔧 Configuration Files Updated

### `forge.config.cjs`

- Added production code signing configuration
- Enhanced security metadata
- Proper app identification

### `electron/main.ts`

- Enhanced User-Agent for Google compatibility
- Security headers for OAuth flows
- Improved session management
- SSL/TLS configuration

### `entitlements.plist` (macOS)

- Configured for hardened runtime
- Required permissions for OAuth
- Camera/microphone access for web apps

## 🧪 Testing the Security Improvements - **Updated User-Agent Test**

1. **Build the app**:

   ```bash
   npm run build
   npm run make
   ```

2. **Test Google Sign-In**:

   - Navigate to Gmail or Google services
   - Try signing in - should work without "insecure" warning

3. **Check User-Agent** (UPDATED):

   - Visit `https://www.whatismybrowser.com/`
   - Should show enhanced Chrome User-Agent (Chrome 139+)
   - Should NOT show "out of date" warning

4. **Test Gmail Login**:
   - Navigate to `https://accounts.google.com/`
   - Try Google Sign-In
   - Should proceed without security warnings

## ✅ **Current Status (August 2025)**

Your browser detection shows:

- **Detected as**: Chrome 139 on Windows 10 ✅
- **Security Level**: Enhanced with app identification ✅
- **OAuth Compatibility**: Configured for Google services ✅

**Note**: The previous Chrome 131 detection was causing "out of date" warnings, which made Google treat the app as potentially insecure. Updated to Chrome 139.

## 🔐 Security Checklist for Production

- [ ] Code signing certificate obtained
- [ ] App built with `NODE_ENV=production`
- [ ] Google OAuth app configured with correct Bundle ID
- [ ] User-Agent includes app identification
- [ ] Security headers properly configured
- [ ] SSL/TLS verification enabled
- [ ] App distributed through official channels (App Store recommended)

## 🚨 Important Notes

1. **Development vs Production**: The app will be more secure in production builds with proper code signing
2. **User-Agent**: The enhanced User-Agent helps Google recognize your app as legitimate
3. **Code Signing**: This is the most critical factor - unsigned apps will always be treated as potentially insecure
4. **App Store**: Distribution through official app stores provides the highest trust level

## 🔄 Next Steps

1. Obtain code signing certificates for your target platforms
2. Configure Google OAuth app with production settings
3. Build and sign the app for production
4. Test OAuth flows in the signed build
5. Consider App Store distribution for maximum trust

The implemented changes should significantly improve Google's trust in your application, especially when combined with proper code signing.
