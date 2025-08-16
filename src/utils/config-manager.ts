/**
 * Configuration manager utility
 * Provides unified access to configuration values from both environment variables and system settings
 */

import { DatabaseService } from '../lib/supabase';

// Cache for system settings
const systemSettingsCache: Record<string, string> = {};

// Settings that ONLY exist in system_settings table and NEVER in environment_variables
const SETTINGS = [
  'VAULT_INTEGRATION_ENABLED',
  'MAX_CONCURRENT_SESSIONS'
];

// Essential Supabase variables that must come from local environment
const ESSENTIAL_DB_VARS = [
  'NEXT_PUBLIC_SUPABASE_URL',
  'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY'
];

/**
 * Get a configuration value from either environment variables or system settings
 * For system settings that exclusively exist in the system_settings table, this will only check there
 * 
 * @param key The key to look up
 * @param defaultValue Optional default value if not found
 * @returns The configuration value or defaultValue if not found
 */
export async function getConfig(key: string, defaultValue: string = ''): Promise<string> {
  // For essential Supabase credentials that MUST come from local environment
  // (these are needed to connect to the database in the first place)
  if (ESSENTIAL_DB_VARS.includes(key)) {
    // For these critical keys, always prefer local environment variables
    const localValue = import.meta.env[key] || process.env[key] || defaultValue;
    if (localValue !== defaultValue) {
      return localValue;
    }
  }
  
  // For settings that must only exist in system_settings
  if (SETTINGS.includes(key)) {
    // Try to get from cache first
    if (systemSettingsCache[key]) {
      return systemSettingsCache[key];
    }
    
    // Fetch from database
    try {
      const value = await DatabaseService.getSystemSettingByKey(key.toLowerCase());
      if (value !== null) {
        // Store in cache
        systemSettingsCache[key] = value;
        return value;
      }
      // If not found, return default value - NEVER fall back to environment_variables
      return defaultValue;
    } catch (error) {
      console.error(`Error fetching setting ${key} from system_settings:`, error);
      return defaultValue;
    }
  }
  
  // For all other settings, get from environment
  // This is handled by the Electron environment service that already knows to check environment_variables table
  if (typeof window !== 'undefined' && window.secureBrowser?.system?.getEnvironment) {
    try {
      // Get environment variables from main process (includes database vars when use_database_env_variables=true)
      const envString = await window.secureBrowser.system.getEnvironment();
      const envVars = JSON.parse(envString);
      
      // Check for the variable in both uppercase and original case
      const upperKey = key.toUpperCase();
      if (envVars[upperKey] !== undefined) {
        return envVars[upperKey];
      }
      if (envVars[key] !== undefined) {
        return envVars[key];
      }
      
      return defaultValue;
    } catch (error) {
      console.error(`Error getting environment variable ${key}:`, error);
      return defaultValue;
    }
  }

  // Fallback to local environment variables (not likely to be used in production)
  return process.env[key] || import.meta.env?.[key] || defaultValue;
}

/**
 * Get a boolean configuration value
 * 
 * @param key The key to look up
 * @param defaultValue Optional default value if not found
 * @returns The boolean value
 */
export async function getBooleanConfig(key: string, defaultValue: boolean = false): Promise<boolean> {
  const value = await getConfig(key, defaultValue.toString());
  return value === 'true' || value === '1' || value === 'yes';
}

/**
 * Get a numeric configuration value
 * 
 * @param key The key to look up
 * @param defaultValue Optional default value if not found
 * @returns The numeric value
 */
export async function getNumericConfig(key: string, defaultValue: number = 0): Promise<number> {
  const value = await getConfig(key, defaultValue.toString());
  const parsed = parseFloat(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

/**
 * React hook for configuration values (simplified version)
 * In a real implementation, you'd want to add state management and rerendering capability
 * 
 * @param key The key to look up
 * @param defaultValue Optional default value if not found
 * @returns The configuration value or defaultValue if not found
 */
export function useConfig(_key: string, _defaultValue: string = ''): string {
  // This is just a placeholder - in a real implementation, you'd want to use useState and useEffect
  // and handle the async nature of getConfig
  return '';
}
