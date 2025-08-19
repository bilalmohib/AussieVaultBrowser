import { createClient } from '@supabase/supabase-js';

// Cache for environment variables
let environmentCache: Record<string, string> | null = null;
let useDbEnvironment = false;

// Essential Supabase variables that must come from local environment
const ESSENTIAL_DB_VARS = [
  'NEXT_PUBLIC_SUPABASE_URL',
  'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY'
];

/**
 * Initialize the environment service
 * This should be called early in the app lifecycle
 */
export async function initEnvironmentService() {
  // CRITICAL: These specific Supabase connection variables MUST come from local environment
  // They are required to connect to the database initially
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.VITE_SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.VITE_SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    console.log('Supabase credentials not found, using local environment variables');
    return;
  }
  
  console.log('Initializing with Supabase credentials from local environment');
  
  // Initialize environmentCache with essential DB vars from local environment
  environmentCache = {};
  ESSENTIAL_DB_VARS.forEach(key => {
    const value = process.env[key];
    if (value) {
      environmentCache![key] = value;
      console.log(`Loaded essential DB credential: ${key}`);
    }
  });

  const supabase = createClient(supabaseUrl, supabaseKey);
  
  // Check if we should use database environment variables
  try {
    const { data, error } = await supabase
      .from('system_settings')
      .select('value')
      .eq('key', 'use_database_env_variables')
      .single();
    
    if (error) {
      console.error('Error fetching use_database_env_variables setting:', error);
      return;
    }
    
    useDbEnvironment = data?.value === 'true';
    console.log(`Environment source: ${useDbEnvironment ? 'Database' : 'Local'}`);
    console.log(`use_database_env_variables is set to: ${data?.value}`);
    
    if (useDbEnvironment) {
      // Load environment variables from database
      await loadEnvironmentVariablesFromDb(supabase);
      
      // Load system settings for moved settings
      await loadSystemSettings(supabase);
      
      // Verify that environment variables were loaded from database
      if (environmentCache && Object.keys(environmentCache).length > 0) {
        console.log(`Successfully loaded ${Object.keys(environmentCache).length} environment variables from database`);
        console.log('Sample environment variables loaded:', 
          Object.keys(environmentCache)
            .filter(key => !ESSENTIAL_DB_VARS.includes(key))
            .slice(0, 3)
            .map(key => `${key}: ${environmentCache![key].substring(0, 10)}...`));
      } else {
        console.error('Failed to load environment variables from database or no variables found');
      }
    }
  } catch (error) {
    console.error('Error checking environment source:', error);
  }
}

/**
 * Load specific system settings that exist ONLY in system_settings table
 * These settings must never be in environment_variables table
 */
async function loadSystemSettings(supabase: any) {
  try {
    // Get the system settings for settings that must only be in system_settings
    const { data, error } = await supabase
      .from('system_settings')
      .select('key, value')
      .in('key', SETTINGS.map(key => key.toLowerCase()));
    
    if (error) throw error;
    
    // Update the cache with the values
    data.forEach((setting: { key: string, value: string }) => {
      const upperKey = setting.key.toUpperCase();
      systemSettingsCache[upperKey] = setting.value;
    });
    
    console.log(`Loaded ${data.length} system settings from database`);
  } catch (error) {
    console.error('Error loading system settings from database:', error);
  }
}

/**
 * Load all environment variables from the database
 */
async function loadEnvironmentVariablesFromDb(supabase: any) {
  try {
    const { data, error } = await supabase
      .from('environment_variables')
      .select('key, value, category');

    if (error) throw error;

    // Preserve essential DB variables that should come from local environment
    const essentialDbVars: Record<string, string> = {};
    if (environmentCache) {
      ESSENTIAL_DB_VARS.forEach(key => {
        if (environmentCache![key]) {
          essentialDbVars[key] = environmentCache![key];
        }
      });
    }
    
    // Create a map of environment variables
    environmentCache = {...essentialDbVars}; // Start with essential DB vars from local env
    
    data.forEach((env: { key: string, value: string }) => {
      // Convert key to uppercase for consistency with process.env
      const upperKey = env.key.toUpperCase();
      
      // Don't override essential DB variables that must come from local environment
      if (!ESSENTIAL_DB_VARS.includes(upperKey)) {
        environmentCache![upperKey] = env.value;
      }
    });
    
    console.log(`Loaded ${data.length} environment variables from database`);
  } catch (error) {
    console.error('Error loading environment variables from database:', error);
  }
}

// Settings that ONLY exist in system_settings table and NEVER in environment_variables
const SETTINGS = [
  'VAULT_INTEGRATION_ENABLED',
  'MAX_CONCURRENT_SESSIONS'
];

// Cache for system settings
const systemSettingsCache: Record<string, string> = {};

/**
 * Get an environment variable
 * @param key The environment variable key
 * @param defaultValue Optional default value if the environment variable is not found
 */
export function getEnv(key: string, defaultValue: string = ''): string {
  // CRITICAL: These specific Supabase connection variables MUST come from local environment
  // They are required to connect to the database initially
  if (ESSENTIAL_DB_VARS.includes(key)) {
    const localValue = process.env[key] || defaultValue;
    // Store in cache for consistency
    if (localValue !== defaultValue && environmentCache) {
      environmentCache[key] = localValue;
    }
    return localValue;
  }
  
  // These settings must only be accessed from system_settings, NEVER from environment_variables
  if (SETTINGS.includes(key)) {
    // Use the cached system setting if available
    if (systemSettingsCache[key]) {
      return systemSettingsCache[key];
    }
    
    // If not in cache, return the default - these settings should never be in environment_variables
    return defaultValue;
  }
  
  // For all other settings:
  // If we're using database environment variables and the cache is loaded
  if (useDbEnvironment && environmentCache) {
    // Check if the key exists in environmentCache (try uppercase version first, then as-is)
    const upperKey = key.toUpperCase();
    if (environmentCache[upperKey] !== undefined) {
      return environmentCache[upperKey] || defaultValue;
    }
    if (environmentCache[key] !== undefined) {
      return environmentCache[key] || defaultValue;
    }
  }

  // Otherwise use local environment variables
  return process.env[key] || defaultValue;
}

/**
 * Get all environment variables as an object
 * This is used by the system-get-environment handler
 */
export function getAllEnvVars(): Record<string, string> {
  const envVars: Record<string, string> = {};
  
  // Define the list of environment variables to expose to the renderer
  const envVarKeys = [
    'NODE_ENV',
    'APP_NAME',
    'APP_VERSION',
    'SECURITY_BLOCK_DOWNLOADS',
    'SECURITY_HTTPS_ONLY',
    'SECURITY_FAIL_CLOSED_VPN',
    'SECURITY_BLOCK_DEVTOOLS',
    'VPN_PROVIDER',
    'VPN_SERVER_REGION',
    'VPN_AUTO_CONNECT',
    'VPN_FAIL_CLOSED',
    'WIREGUARD_CONFIG_PATH',
    'WIREGUARD_ENDPOINT',
    'VAULT_PROVIDER',
    'OP_SERVICE_ACCOUNT_TOKEN',
    'OP_SHAREPOINT_ITEM_ID',
    'ONEPASSWORD_EXTENSION_ENABLED',
    'ONEPASSWORD_AUTO_DETECT',
    'ONEPASSWORD_EXTENSION_ID',
    'SHAREPOINT_TENANT_URL',
    'SHAREPOINT_AUTO_LOGIN',
    'SHAREPOINT_DEFAULT_ACCESS_LEVEL',
    'SHAREPOINT_DOCUMENT_LIBRARIES',
    'SHAREPOINT_BASE_URL',
    'LEVEL1_DOMAINS',
    'LEVEL2_DOMAINS',
    'LEVEL3_ENABLED',
    'LOG_LEVEL',
    'LOG_FILE_PATH',
    'NEXT_PUBLIC_SUPABASE_URL',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'NEXT_PUBLIC_APP_URL',
    'NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY',
    'CLERK_SECRET_KEY',
    'MSAL_CLIENT_ID',
    'MSAL_TENANT_ID',
    'MSAL_REDIRECT_URI',
    'MSAL_CLIENT_SECRET',
    'SHAREPOINT_BASE_URL',
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET'
  ];
  
  // Add system settings to the environment variables list for compatibility
  for (const key of SETTINGS) {
    if (!envVarKeys.includes(key)) {
      envVarKeys.push(key);
    }
  }
  
  // First add essential database connection variables from local environment
  // These MUST come from local environment
  for (const key of ESSENTIAL_DB_VARS) {
    envVars[key] = process.env[key] || '';
  }
  
  // For other variables, use database if available
  if (useDbEnvironment && environmentCache) {
    console.log(`Using database environment variables: ${Object.keys(environmentCache).length} variables available`);
    
    // Add environment variables from the database cache (excluding essential DB vars)
    for (const key in environmentCache) {
      // Skip essential DB vars as we've already added them from local environment
      if (!ESSENTIAL_DB_VARS.includes(key)) {
        envVars[key] = environmentCache[key];
      }
    }
    
    // Still check for any missing keys from the predefined list
    for (const key of envVarKeys) {
      if (envVars[key] === undefined && !ESSENTIAL_DB_VARS.includes(key)) {
        envVars[key] = getEnv(key, '');
      }
    }
  } else {
    // If not using database or cache isn't loaded, use getEnv for each key
    console.log('Using local environment variables');
    for (const key of envVarKeys) {
      if (!ESSENTIAL_DB_VARS.includes(key)) { // Skip essential DB vars as we've already added them
        envVars[key] = getEnv(key, '');
      }
    }
  }
  
  // Verify essential DB variables are present
  ESSENTIAL_DB_VARS.forEach(key => {
    if (!envVars[key]) {
      console.warn(`Essential database variable ${key} is missing!`);
    }
  });
  
  return envVars;
}

/**
 * Check if we are using database environment variables
 */
export function isUsingDatabaseEnv(): boolean {
  return useDbEnvironment;
}
