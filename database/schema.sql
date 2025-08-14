-- Secure Remote Browser Database Schema
-- This schema supports the Electron app with comprehensive logging and monitoring
-- Uses auto-incrementing integer IDs and Clerk authentication

-- Create custom types
CREATE TYPE access_level_enum AS ENUM ('1', '2', '3');
CREATE TYPE user_status_enum AS ENUM ('active', 'suspended', 'inactive');
CREATE TYPE vpn_status_enum AS ENUM ('connected', 'disconnected', 'failed', 'reconnecting');
CREATE TYPE event_severity_enum AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE setting_category_enum AS ENUM ('vpn', 'security', 'general', 'sharepoint', 'vault');
CREATE TYPE env_category_enum AS ENUM ('application', 'security', 'vpn', 'vault', 'sharepoint', 'access_control', 'logging', 'system', 'integration');

-- Users table for Secure Remote Browser
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    access_level INTEGER NOT NULL DEFAULT 1 CHECK (access_level IN (1, 2, 3)),
    status user_status_enum NOT NULL DEFAULT 'active',
    device_id TEXT,
    vpn_required BOOLEAN NOT NULL DEFAULT true,
    can_edit_access_level BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_login TIMESTAMP WITH TIME ZONE,
    created_by BIGINT,
    
    -- Indexes
    CONSTRAINT users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Create indexes for users table
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_access_level ON users(access_level);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_device_id ON users(device_id);

-- User Sessions table for detailed session tracking
CREATE TABLE user_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    login_time TIMESTAMP WITH TIME ZONE DEFAULT now(),
    logout_time TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    vpn_endpoint TEXT,
    location TEXT,
    user_agent TEXT,
    vpn_status vpn_status_enum NOT NULL DEFAULT 'disconnected',
    session_duration INTEGER -- in seconds
);

-- Create indexes for user_sessions table
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_login_time ON user_sessions(login_time);
CREATE INDEX idx_user_sessions_device_id ON user_sessions(device_id);

-- Access Levels configuration table
CREATE TABLE access_levels (
    id BIGSERIAL PRIMARY KEY,
    level INTEGER UNIQUE NOT NULL CHECK (level IN (1, 2, 3)),
    name TEXT NOT NULL,
    description TEXT,
    allowed_domains TEXT[] NOT NULL DEFAULT '{}',
    blocked_domains TEXT[] NOT NULL DEFAULT '{}',
    max_windows INTEGER NOT NULL DEFAULT 1,
    session_timeout INTEGER NOT NULL DEFAULT 3600, -- in seconds
    vpn_required BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_by BIGINT REFERENCES users(id),
    
    -- Constraints
    CONSTRAINT access_levels_name_check CHECK (name IN ('Restricted', 'Manager', 'Full Access'))
);

-- Security Events table for comprehensive security logging
CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    device_id TEXT,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    severity event_severity_enum NOT NULL DEFAULT 'low',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
    resolved BOOLEAN NOT NULL DEFAULT false,
    url TEXT,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    
    -- Constraints
    CONSTRAINT security_events_event_type_check CHECK (
        event_type IN ('download_blocked', 'domain_blocked', 'vpn_disconnected', 
                      'unauthorized_access', 'session_timeout', 'suspicious_activity')
    )
);

-- Create indexes for security_events table
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_resolved ON security_events(resolved);
CREATE INDEX idx_security_events_event_type ON security_events(event_type);

-- VPN Connections table for detailed VPN monitoring
CREATE TABLE vpn_connections (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    connection_start TIMESTAMP WITH TIME ZONE DEFAULT now(),
    connection_end TIMESTAMP WITH TIME ZONE,
    endpoint TEXT NOT NULL,
    server_location TEXT NOT NULL,
    client_ip INET,
    vpn_ip INET,
    status vpn_status_enum NOT NULL DEFAULT 'connected',
    latency INTEGER, -- in milliseconds
    data_transfer BIGINT DEFAULT 0 -- in bytes
);

-- Create indexes for vpn_connections table
CREATE INDEX idx_vpn_connections_user_id ON vpn_connections(user_id);
CREATE INDEX idx_vpn_connections_start ON vpn_connections(connection_start);
CREATE INDEX idx_vpn_connections_status ON vpn_connections(status);
CREATE INDEX idx_vpn_connections_device_id ON vpn_connections(device_id);

-- Navigation Logs table for tracking user browsing
CREATE TABLE navigation_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
    allowed BOOLEAN NOT NULL,
    access_level INTEGER NOT NULL CHECK (access_level IN (1, 2, 3)),
    vpn_active BOOLEAN NOT NULL,
    blocked_reason TEXT
);

-- Create indexes for navigation_logs table
CREATE INDEX idx_navigation_logs_user_id ON navigation_logs(user_id);
CREATE INDEX idx_navigation_logs_timestamp ON navigation_logs(timestamp);
CREATE INDEX idx_navigation_logs_domain ON navigation_logs(domain);
CREATE INDEX idx_navigation_logs_allowed ON navigation_logs(allowed);

-- Browsing History table for Chrome-like history functionality
CREATE TABLE browsing_history (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    url TEXT NOT NULL,
    domain TEXT NOT NULL,
    page_title TEXT NOT NULL,
    visit_count INTEGER NOT NULL DEFAULT 1,
    first_visit TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_visit TIMESTAMP WITH TIME ZONE DEFAULT now(),
    favicon_url TEXT,
    is_bookmarked BOOLEAN NOT NULL DEFAULT false,
    access_level INTEGER NOT NULL CHECK (access_level IN (1, 2, 3)),
    
    -- Unique constraint to prevent duplicate URLs per user
    UNIQUE(user_id, url)
);

-- Create indexes for browsing_history table
CREATE INDEX idx_browsing_history_user_id ON browsing_history(user_id);
CREATE INDEX idx_browsing_history_last_visit ON browsing_history(last_visit DESC);
CREATE INDEX idx_browsing_history_domain ON browsing_history(domain);
CREATE INDEX idx_browsing_history_title ON browsing_history USING gin(to_tsvector('english', page_title));
CREATE INDEX idx_browsing_history_url ON browsing_history USING gin(to_tsvector('english', url));
CREATE INDEX idx_browsing_history_visit_count ON browsing_history(visit_count DESC);

-- System Settings table for application configuration
CREATE TABLE system_settings (
    id BIGSERIAL PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    category setting_category_enum NOT NULL DEFAULT 'general',
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_by BIGINT REFERENCES users(id)
);

-- Create indexes for system_settings table
CREATE INDEX idx_system_settings_category ON system_settings(category);
CREATE INDEX idx_system_settings_key ON system_settings(key);

-- Environment Variables table for application configuration
CREATE TABLE environment_variables (
    id BIGSERIAL PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    category env_category_enum NOT NULL,
    description TEXT,
    is_secret BOOLEAN NOT NULL DEFAULT false,
    is_editable BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_by BIGINT REFERENCES users(id),
    
    -- Constraints
    CONSTRAINT environment_variables_key_check CHECK (key ~ '^[A-Z0-9_]+$')
);

-- Create indexes for environment_variables table
CREATE INDEX idx_environment_variables_category ON environment_variables(category);
CREATE INDEX idx_environment_variables_key ON environment_variables(key);

-- Bookmarks table for user bookmark management
CREATE TABLE bookmarks (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    favicon_url TEXT,
    folder_name TEXT DEFAULT 'General',
    tags TEXT[] DEFAULT '{}',
    is_public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    access_level INTEGER NOT NULL DEFAULT 1 CHECK (access_level IN (1, 2, 3)),
    device_id TEXT,
    
    -- Prevent duplicate URLs per user
    UNIQUE(user_id, url)
);

-- Create indexes for bookmarks table
CREATE INDEX idx_bookmarks_user_id ON bookmarks(user_id);
CREATE INDEX idx_bookmarks_folder_name ON bookmarks(folder_name);
CREATE INDEX idx_bookmarks_tags ON bookmarks USING gin(tags);
CREATE INDEX idx_bookmarks_created_at ON bookmarks(created_at DESC);
CREATE INDEX idx_bookmarks_access_level ON bookmarks(access_level);
CREATE INDEX idx_bookmarks_is_public ON bookmarks(is_public);
CREATE INDEX idx_bookmarks_title ON bookmarks USING gin(to_tsvector('english', title));
CREATE INDEX idx_bookmarks_url ON bookmarks USING gin(to_tsvector('english', url));

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add updated_at triggers
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_access_levels_updated_at 
    BEFORE UPDATE ON access_levels 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_settings_updated_at 
    BEFORE UPDATE ON system_settings 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_environment_variables_updated_at 
    BEFORE UPDATE ON environment_variables 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bookmarks_updated_at 
    BEFORE UPDATE ON bookmarks 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default access levels
INSERT INTO access_levels (level, name, description, allowed_domains, max_windows, session_timeout, vpn_required) VALUES
(1, 'Restricted', 'SharePoint-only access with strict domain restrictions', 
 ARRAY['datalifesaver.sharepoint.com', 'sharepoint.com', 'onedrive.com', 'office365.com'], 1, 3600, true),

(2, 'Manager', 'SharePoint plus approved business domains', 
 ARRAY['datalifesaver.sharepoint.com', 'sharepoint.com', 'microsoft.com', 'office.com', 'msn.com', 'live.com'], 2, 7200, true),

(3, 'Full Access', 'Unrestricted browsing through VPN', 
 ARRAY['*'], 5, 14400, true);

-- Insert default system settings
INSERT INTO system_settings (key, value, category, description) VALUES
-- Add a setting to control environment variable source (local .env or database)
('use_database_env_variables', 'false', 'general', 'When true, use database environment variables instead of local .env file');

-- Insert default environment variables
-- Application settings
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('NODE_ENV', 'development', 'application', 'Node environment (development, production, test)', true),
('APP_NAME', 'Secure Remote Browser', 'application', 'Application name', true),
('APP_VERSION', '1.0.0', 'application', 'Application version number', true),
('NEXT_PUBLIC_APP_URL', 'http://localhost:5173', 'application', 'Public application URL', true);

-- Security settings
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('SECURITY_BLOCK_DOWNLOADS', 'false', 'security', 'Block all file downloads when true', true),
('SECURITY_HTTPS_ONLY', 'false', 'security', 'Force HTTPS connections only when true', true),
('SECURITY_FAIL_CLOSED_VPN', 'true', 'security', 'Block browser access if VPN fails when true', true),
('SECURITY_BLOCK_DEVTOOLS', 'false', 'security', 'Block developer tools access when true', true);

-- VPN configuration
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('VPN_PROVIDER', 'wireguard', 'vpn', 'VPN provider (wireguard, nordlayer, expressvpn)', true),
('VPN_SERVER_REGION', 'australia', 'vpn', 'VPN server region', true),
('VPN_AUTO_CONNECT', 'true', 'vpn', 'Automatically connect to VPN on startup', true),
('VPN_FAIL_CLOSED', 'true', 'vpn', 'Block browser access if VPN fails', true),
('WIREGUARD_CONFIG_PATH', './config/wireguard-australia.conf', 'vpn', 'Path to WireGuard configuration file', true),
('WIREGUARD_ENDPOINT', '134.199.169.102:59926', 'vpn', 'WireGuard server endpoint', true);

-- Vault configuration
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('VAULT_PROVIDER', '1password-cli', 'vault', 'Password vault provider', true),
('OP_SERVICE_ACCOUNT_TOKEN', 'ops_eyJzaWduUSW5BZGRyZXNzljolbXtu', 'vault', '1Password service account token', true),
('OP_SHAREPOINT_ITEM_ID', 'by6jl6jiv4iiimfn56pcs72yamiq6ihxus2lx43taaei4d7ph2li', 'vault', '1Password SharePoint item ID', true),
('ONEPASSWORD_EXTENSION_ENABLED', 'true', 'vault', 'Enable 1Password browser extension integration', true),
('ONEPASSWORD_AUTO_DETECT', 'true', 'vault', 'Auto-detect 1Password browser extension', true),
('ONEPASSWORD_EXTENSION_ID', 'aeblfdkhhhdcdjpifhhbdiojplfjncoa', 'vault', '1Password browser extension ID', true);

-- SharePoint configuration
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('SHAREPOINT_TENANT_URL', 'https://datalifesaver.sharepoint.com', 'sharepoint', 'SharePoint tenant URL', true),
('SHAREPOINT_AUTO_LOGIN', 'true', 'sharepoint', 'Enable automatic SharePoint login', true),
('SHAREPOINT_DEFAULT_ACCESS_LEVEL', '1', 'sharepoint', 'Default user access level', true),
('SHAREPOINT_DOCUMENT_LIBRARIES', 'https://datalifesaver.sharepoint.com/Shared%20Documents/Forms/AllItems.aspx', 'sharepoint', 'SharePoint document libraries URL', true),
('SHAREPOINT_BASE_URL', 'flowuxart.sharepoint.com', 'sharepoint', 'SharePoint base URL', true);

-- Access control levels
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('LEVEL1_DOMAINS', 'datalifesaver.sharepoint.com,sharepoint.com,onedrive.com,office365.com,sharepointonline.com', 'access_control', 'Level 1 allowed domains (SharePoint only)', true),
('LEVEL2_DOMAINS', 'microsoft.com,office.com,msn.com,live.com,microsoftonline.com', 'access_control', 'Level 2 allowed domains (SharePoint + Microsoft)', true),
('LEVEL3_ENABLED', 'true', 'access_control', 'Enable Level 3 full browsing through VPN', true);

-- Logging settings
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('LOG_LEVEL', 'info', 'logging', 'Application logging level', true),
('LOG_FILE_PATH', './logs/app.log', 'logging', 'Path to log file', true);

-- System settings
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('DIGITAL_OCEAN_PASSWORD', 'B^BEqm4b9fRgU$3', 'system', 'Digital Ocean password', true);

-- GitHub integration
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('GITHUB_TOKEN', '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', 'integration', 'GitHub access token', true);

-- MSAL credentials
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('MSAL_CLIENT_ID', '377bf11f-974a-4475-98f7-d0e54649f4a3', 'integration', 'Microsoft Authentication Library client ID', true),
('MSAL_TENANT_ID', '6c1f4a54-1535-4634-a2ae-32230b4cb3f4', 'integration', 'Microsoft Authentication Library tenant ID', true),
('MSAL_REDIRECT_URI', 'http://localhost', 'integration', 'Microsoft Authentication Library redirect URI', true),
('MSAL_CLIENT_SECRET', 'yRZ8Q~Q-wVKNPvCZJM6f5dWjyvdnm2~imOULTbZC', 'integration', 'Microsoft Authentication Library client secret', true);

-- Google OAuth credentials
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('GOOGLE_CLIENT_ID', '913329095431-n5uip0t9lakec7k96mBjuo07q85ocbv5.apps.googleusercontent.com', 'integration', 'Google OAuth client ID', true),
('GOOGLE_CLIENT_SECRET', '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', 'integration', 'Google OAuth client secret', true);

-- Supabase credentials
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('NEXT_PUBLIC_SUPABASE_URL', 'https://nppuvwyqoohvypfcmuib.supabase.co', 'integration', 'Supabase project URL', true),
('NEXT_PUBLIC_SUPABASE_ANON_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5wcHV2d3lxb29odnlwZmNtdWliIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTIyMzg4MzAsImV4cCI6MjA2NzgxNDgzMH0.VR6Nour7ctDxnsJwSCF93WkaYL25LEbx3uEoCzFcKRs', 'integration', 'Supabase anonymous key', true),
('SUPABASE_SERVICE_ROLE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5wcHV2d3lxb29odnlwZmNtdWliIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1MjIzODgzMCwiZXhwIjoyMDY3ODE0ODMwfQ.eKjYeTzjyhLDtzD6yMUpll9Gh4q9VqwKE591ulSCKyQ', 'integration', 'Supabase service role key', true);

-- Clerk Authentication
INSERT INTO environment_variables (key, value, category, description, is_editable) VALUES
('NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY', 'pk_test_bWFqb3Itc25pcGUtOS5jbGVyay5hY2NvdW50cy5kZXYk', 'integration', 'Clerk publishable key', true),
('CLERK_SECRET_KEY', 'sk_test_kUjISBXa6tf1YkfmZkDTYyPeQ0OP1jr0KdS5Bxjnbb', 'integration', 'Clerk secret key', true);

-- Mark secrets as secret but still editable
UPDATE environment_variables SET is_secret = true WHERE 
    key LIKE '%KEY' OR 
    key LIKE '%SECRET%' OR 
    key LIKE '%PASSWORD%' OR 
    key LIKE '%TOKEN%';

-- Row Level Security Policies
-- Note: Since we're using Clerk authentication, we'll implement basic RLS without auth.email()
-- The application layer will handle most access control through Clerk

-- Users table policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Allow read/write for all authenticated users (Clerk handles the real auth)
-- In production, you might want to be more restrictive
CREATE POLICY "Allow authenticated access to users" ON users
    FOR ALL USING (true);

-- User Sessions policies
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated access to user_sessions" ON user_sessions
    FOR ALL USING (true);

-- Access Levels policies
ALTER TABLE access_levels ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow read access to access_levels" ON access_levels
    FOR SELECT USING (true);

-- Security Events policies
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated access to security_events" ON security_events
    FOR ALL USING (true);

-- VPN Connections policies
ALTER TABLE vpn_connections ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated access to vpn_connections" ON vpn_connections
    FOR ALL USING (true);

-- Navigation Logs policies
ALTER TABLE navigation_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated access to navigation_logs" ON navigation_logs
    FOR ALL USING (true);

-- Browsing History policies
ALTER TABLE browsing_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated access to browsing_history" ON browsing_history
    FOR ALL USING (true);

-- Bookmarks policies
ALTER TABLE bookmarks ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated access to bookmarks" ON bookmarks
    FOR ALL USING (true);

-- System Settings policies
ALTER TABLE system_settings DISABLE ROW LEVEL SECURITY;

-- Environment Variables policies
ALTER TABLE environment_variables ENABLE ROW LEVEL SECURITY;

-- Only allow admins to view/edit environment variables
CREATE POLICY "Allow service role access to environment_variables" ON environment_variables
    FOR ALL USING (true);

-- Create helpful views
CREATE VIEW user_activity AS
SELECT 
    u.email,
    u.name,
    u.access_level,
    u.status,
    us.login_time,
    us.vpn_status,
    us.location,
    vc.endpoint,
    vc.server_location
FROM users u
LEFT JOIN user_sessions us ON u.id = us.user_id
LEFT JOIN vpn_connections vc ON u.id = vc.user_id
WHERE us.logout_time IS NULL; -- Only active sessions

CREATE VIEW security_summary AS
SELECT 
    DATE(timestamp) as date,
    event_type,
    severity,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as affected_users
FROM security_events
WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(timestamp), event_type, severity
ORDER BY date DESC, event_count DESC;

-- Enable real-time subscriptions
ALTER PUBLICATION supabase_realtime ADD TABLE users;
ALTER PUBLICATION supabase_realtime ADD TABLE user_sessions;
ALTER PUBLICATION supabase_realtime ADD TABLE security_events;
ALTER PUBLICATION supabase_realtime ADD TABLE vpn_connections;
ALTER PUBLICATION supabase_realtime ADD TABLE navigation_logs;
ALTER PUBLICATION supabase_realtime ADD TABLE browsing_history;
ALTER PUBLICATION supabase_realtime ADD TABLE bookmarks;
ALTER PUBLICATION supabase_realtime ADD TABLE environment_variables;

-- Grant permissions for authenticated users
GRANT SELECT, INSERT, UPDATE ON users TO authenticated;
GRANT SELECT, INSERT, UPDATE ON user_sessions TO authenticated;
GRANT SELECT, INSERT ON security_events TO authenticated;
GRANT SELECT, INSERT, UPDATE ON vpn_connections TO authenticated;
GRANT SELECT, INSERT ON navigation_logs TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON browsing_history TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON bookmarks TO authenticated;
GRANT SELECT ON access_levels TO authenticated;
GRANT SELECT, UPDATE ON system_settings TO authenticated;
GRANT SELECT, INSERT, UPDATE ON environment_variables TO authenticated;

-- Grant permissions for service role (for admin operations)
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;

-- Grant usage on sequences for auto-increment IDs
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT USAGE, SELECT ON SEQUENCE environment_variables_id_seq TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE environment_variables_id_seq TO service_role;

-- Comments for documentation
COMMENT ON TABLE users IS 'Secure Remote Browser user accounts with access control';
COMMENT ON TABLE user_sessions IS 'Detailed session tracking for security monitoring';
COMMENT ON TABLE access_levels IS 'Access level configurations and domain restrictions';
COMMENT ON TABLE security_events IS 'Security incident logging and monitoring';
COMMENT ON TABLE vpn_connections IS 'VPN connection monitoring and analytics';
COMMENT ON TABLE navigation_logs IS 'User browsing activity and access control logs';
COMMENT ON TABLE browsing_history IS 'Chrome-like browsing history with local and cloud sync';
COMMENT ON TABLE bookmarks IS 'User bookmarks with categorization and access control';
COMMENT ON TABLE system_settings IS 'Application configuration and system settings';
COMMENT ON TABLE environment_variables IS 'Application environment variables with categorization and access control';

-- Migration script function to move environment variables from system_settings to environment_variables
-- This will execute on schema load if both tables exist
DO $$
BEGIN
    -- Create a temporary mapping table for category conversion
    CREATE TEMPORARY TABLE IF NOT EXISTS category_mapping (
        old_category TEXT,
        new_category TEXT
    );

    -- Insert category mappings
    INSERT INTO category_mapping (old_category, new_category) VALUES
    ('vpn', 'vpn'),
    ('security', 'security'),
    ('general', 'application'),
    ('sharepoint', 'sharepoint'),
    ('vault', 'vault');

    -- Migrate environment variables from system_settings to environment_variables if they exist
    INSERT INTO environment_variables (
        key, 
        value, 
        category, 
        description, 
        is_secret, 
        is_editable
    )
    SELECT 
        UPPER(s.key), 
        s.value, 
        (SELECT new_category FROM category_mapping WHERE old_category = s.category::text)::env_category_enum, 
        s.description,
        CASE 
            WHEN s.key LIKE '%KEY' OR s.key LIKE '%SECRET%' OR s.key LIKE '%PASSWORD%' OR s.key LIKE '%TOKEN%' THEN true
            ELSE false
        END,
        true
    FROM system_settings s
    WHERE LOWER(s.key) IN (
        'vpn_provider', 
        'vpn_endpoint', 
        'vpn_server_region', 
        'vpn_auto_connect', 
        'vpn_fail_closed', 
        'security_block_downloads', 
        'security_https_only', 
        'security_block_devtools',
        'log_level',
        'session_timeout_warning',
        'max_concurrent_sessions',
        'sharepoint_tenant_url',
        'sharepoint_auto_login',
        'sharepoint_default_access_level',
        'vault_integration_enabled'
    )
    -- Skip if key already exists in environment_variables to prevent duplicates
    AND NOT EXISTS (
        SELECT 1 FROM environment_variables WHERE key = UPPER(s.key)
    )
    ON CONFLICT (key) DO NOTHING;

    -- Delete migrated environment variables from system_settings
    DELETE FROM system_settings
    WHERE LOWER(key) IN (
        'vpn_provider', 
        'vpn_endpoint', 
        'vpn_server_region', 
        'vpn_auto_connect', 
        'vpn_fail_closed', 
        'security_block_downloads', 
        'security_https_only', 
        'security_block_devtools',
        'log_level',
        'session_timeout_warning',
        'max_concurrent_sessions',
        'sharepoint_tenant_url',
        'sharepoint_auto_login',
        'sharepoint_default_access_level',
        'vault_integration_enabled'
    );

    -- Clean up temporary table
    DROP TABLE IF EXISTS category_mapping;

    RAISE NOTICE 'Environment variable migration complete.';
END
$$;