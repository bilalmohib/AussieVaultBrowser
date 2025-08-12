export interface IPCheckResult {
  ip: string;
  country: string;
  countryName: string;
  region: string;
  city: string;
  isAustralia: boolean;
}

// Note: Types for window.electronAPI are declared in useVPN.ts. We avoid redefining here to prevent conflicts.

export const checkAustralianIP = async (): Promise<IPCheckResult | null> => {
  try {
    if (window.electronAPI?.vpn?.checkIP) {
      const result = await window.electronAPI.vpn.checkIP();
      return result;
    }
  } catch {
    // ignore
  }
  return null;
};


