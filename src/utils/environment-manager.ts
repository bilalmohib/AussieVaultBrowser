import { createClient } from '@supabase/supabase-js';
import { useState, useEffect } from 'react';

// Types for environment variables
export interface EnvironmentVariable {
  key: string;
  value: string;
  category: EnvironmentCategory;
  description?: string;
  is_secret: boolean;
  is_editable: boolean;
}

export type EnvironmentCategory = 
  | 'application' 
  | 'security' 
  | 'vpn' 
  | 'vault' 
  | 'sharepoint' 
  | 'access_control' 
  | 'logging' 
  | 'system' 
  | 'integration';

// Cache for environment variables
let environmentCache: Record<string, string> | null = null;
let useDbEnvironment = false;

/**
 * Initialize the environment manager
 * This should be called early in the app lifecycle
 */
export async function initEnvironmentManager() {
  // Check if we should use database environment variables
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || import.meta.env?.VITE_SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || import.meta.env?.VITE_SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    console.log('Supabase credentials not found, using local environment variables');
    return;
  }

  const supabase = createClient(supabaseUrl, supabaseKey);
  
  // Check if we should use database environment variables
  try {
    const { data, error } = await supabase
      .from('system_settings')
      .select('value')
      .eq('key', 'use_database_env_variables')
      .single();
    
    if (error) throw error;
    
    useDbEnvironment = data?.value === 'true';
    
    if (useDbEnvironment) {
      await loadEnvironmentVariablesFromDb(supabase);
    }
  } catch (error) {
    console.error('Error checking environment source:', error);
  }
}

/**
 * Load all environment variables from the database
 */
async function loadEnvironmentVariablesFromDb(supabase: any) {
  try {
    const { data, error } = await supabase
      .from('environment_variables')
      .select('key, value');

    if (error) throw error;

    // Create a map of environment variables
    environmentCache = {};
    data.forEach((env: { key: string, value: string }) => {
      environmentCache![env.key] = env.value;
    });
    
    console.log('Loaded environment variables from database');
  } catch (error) {
    console.error('Error loading environment variables from database:', error);
  }
}

/**
 * Get an environment variable
 * @param key The environment variable key
 * @param defaultValue Optional default value if the environment variable is not found
 */
export function getEnv(key: string, defaultValue: string = ''): string {
  // If we're using database environment variables and the cache is loaded
  if (useDbEnvironment && environmentCache) {
    return environmentCache[key] || defaultValue;
  }

  // Otherwise use local environment variables
  return process.env[key] || import.meta.env?.[key] || defaultValue;
}

/**
 * React hook for using environment variables
 * This will re-render the component when the environment variables change
 */
export function useEnvironment(key: string, defaultValue: string = '') {
  const [value, setValue] = useState<string>(getEnv(key, defaultValue));
  
  useEffect(() => {
    // Update value if environment source changes
    setValue(getEnv(key, defaultValue));
    
    // TODO: Subscribe to real-time updates if needed
    
  }, [key, defaultValue]);
  
  return value;
}
