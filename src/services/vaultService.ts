import { VaultCredentials, SharePointConfig } from "@/types";

// Use native fetch (available in Node.js 18+)
const fetchImpl = globalThis.fetch;

// Environment configuration interface
interface VaultConfig {
  provider:
    | "hashicorp"
    | "aws-secrets"
    | "1password"
    | "1password-cli"
    | "azure-keyvault";
  endpoint: string;
  credentials: Record<string, string>;
}

// Vault service for managing shared SharePoint credentials
export class VaultService {
  private vaultProvider:
    | "hashicorp"
    | "aws-secrets"
    | "1password"
    | "1password-cli"
    | "azure-keyvault";
  private vaultEndpoint: string;
  private accessToken: string | null = null;
  private initialized: boolean = false;
  private config: VaultConfig | null = null;

  constructor(
    provider:
      | "hashicorp"
      | "aws-secrets"
      | "1password"
      | "1password-cli"
      | "azure-keyvault" = "hashicorp"
  ) {
    this.vaultProvider = provider;
    this.vaultEndpoint = "";
  }

  // Get environment configuration from Electron main process
  // Future use - environment config loading
  // @ts-expect-error - Future implementation
  private async getEnvironmentConfig(): Promise<VaultConfig> {
    if (this.config) {
      return this.config;
    }

    try {
      // In Electron, we use the secure API bridge instead of direct process.env access
      if (typeof window !== "undefined" && window.secureBrowser) {
        const envConfig = await window.secureBrowser.system.getEnvironment();

        // Parse the environment configuration returned from main process
        const config = JSON.parse(envConfig) as {
          VAULT_PROVIDER?: string;
          VAULT_ADDR?: string;
          VAULT_ROLE_ID?: string;
          VAULT_SECRET_ID?: string;
          AWS_REGION?: string;
          AWS_ACCESS_KEY_ID?: string;
          AWS_SECRET_ACCESS_KEY?: string;
          AZURE_TENANT_ID?: string;
          AZURE_CLIENT_ID?: string;
          AZURE_CLIENT_SECRET?: string;
          AZURE_VAULT_URL?: string;
          OP_CONNECT_HOST?: string;
          OP_CONNECT_TOKEN?: string;
          OP_SERVICE_ACCOUNT_TOKEN?: string;
          OP_SHAREPOINT_ITEM_ID?: string;
        };

        this.config = {
          provider:
            (config.VAULT_PROVIDER as
              | "hashicorp"
              | "aws-secrets"
              | "1password"
              | "1password-cli"
              | "azure-keyvault") || this.vaultProvider,
          endpoint: this.getVaultEndpoint(config),
          credentials: {
            roleId: config.VAULT_ROLE_ID || "",
            secretId: config.VAULT_SECRET_ID || "",
            awsAccessKey: config.AWS_ACCESS_KEY_ID || "",
            awsSecretKey: config.AWS_SECRET_ACCESS_KEY || "",
            awsRegion: config.AWS_REGION || "us-east-1",
            azureTenantId: config.AZURE_TENANT_ID || "",
            azureClientId: config.AZURE_CLIENT_ID || "",
            azureClientSecret: config.AZURE_CLIENT_SECRET || "",
            azureVaultUrl: config.AZURE_VAULT_URL || "",
            opConnectHost: config.OP_CONNECT_HOST || "",
            opConnectToken: config.OP_CONNECT_TOKEN || "",
            opServiceAccountToken: config.OP_SERVICE_ACCOUNT_TOKEN || "",
            opSharePointItemId: config.OP_SHAREPOINT_ITEM_ID || "",
          },
        };

        return this.config;
      } else {
        // Fallback for non-Electron environments (testing, etc.)
        throw new Error(
          "Environment configuration not available. This service requires Electron context."
        );
      }
    } catch (error) {
      throw new Error(
        `Failed to load environment configuration: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  private getVaultEndpoint(config: Record<string, string | undefined>): string {
    switch (this.vaultProvider) {
      case "hashicorp":
        return config.VAULT_ADDR || "http://localhost:8200";
      case "aws-secrets":
        return config.AWS_REGION || "us-east-1";
      case "1password":
        return config.OP_CONNECT_HOST || "";
      case "1password-cli":
        return "https://my.1password.com/api/v1";
      case "azure-keyvault":
        return config.AZURE_VAULT_URL || "";
      default:
        return "http://localhost:8200";
    }
  }

  // Initialize vault connection
  async initialize(): Promise<void> {
    if (this.initialized) {
      return; // Already initialized
    }

    try {
      // Use IPC to get vault status from main process (secure)
      // console.log('🔄 Initializing vault via main process...');

      if (
        typeof window !== "undefined" &&
        window.secureBrowser?.vault?.getVaultStatus
      ) {
        const status = await window.secureBrowser.vault.getVaultStatus();
        // console.log('🔍 Vault status from main process:', status);

        if (
          status &&
          (status.includes("connected") || status === "connected-dev")
        ) {
          this.initialized = true;
          this.vaultProvider = "hashicorp"; // Default for now
          // console.log(`✅ Vault initialized via main process: ${status}`);
          return;
        }
      }

      // Fallback for development
      if (process.env.NODE_ENV === "development") {
        // console.log('🔧 Development mode: vault initialization bypassed');
        this.initialized = true;
        this.vaultProvider = "hashicorp";
        return;
      }

      throw new Error("Unable to initialize vault via main process");
    } catch (error) {
      // console.error('❌ Failed to initialize vault:', error);

      // In development, allow graceful degradation
      if (process.env.NODE_ENV === "development") {
        // console.log('🔧 Development mode: continuing without vault');
        this.initialized = true;
        this.vaultProvider = "hashicorp";
        return;
      }

      throw new Error(
        `Vault error: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  // Get shared SharePoint credentials from vault
  async getSharePointCredentials(): Promise<VaultCredentials> {
    if (!this.initialized) {
      throw new Error(
        "Vault service not initialized. Call initialize() first."
      );
    }

    try {
      // Use IPC to get credentials from main process (secure)
      // console.log('🔑 Requesting SharePoint credentials via main process...');

      if (
        typeof window !== "undefined" &&
        window.secureBrowser?.vault?.getSharePointCredentials
      ) {
        const credentials =
          await window.secureBrowser.vault.getSharePointCredentials();
        // console.log('✅ SharePoint credentials retrieved from main process');

        return {
          sharepointUsername: credentials.username,
          sharepointPassword: credentials.password,
          lastUpdated: new Date(Date.now()), // Use current time since main process handles this
          vaultProvider: this.vaultProvider,
        };
      }

      throw new Error("IPC vault service not available");
    } catch (error) {
      // console.error('❌ Failed to retrieve SharePoint credentials:', error);
      throw new Error(
        `Unable to access SharePoint credentials from vault: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  // Get complete SharePoint configuration
  async getSharePointConfig(): Promise<SharePointConfig> {
    if (!this.initialized) {
      throw new Error(
        "Vault service not initialized. Call initialize() first."
      );
    }

    try {
      const credentials = await this.getSharePointCredentials();

      // For MVP, we'll use environment defaults with vault credentials
      // In production, these would also come from vault

      return {
        tenantUrl: "https://your-tenant.sharepoint.com", // This should come from vault in production
        libraryPath: "/sites/documents/Shared Documents",
        allowedFileTypes: ["pdf", "docx", "xlsx", "pptx"],
        credentials,
      };
    } catch (error) {
      // console.error('❌ Failed to retrieve SharePoint configuration:', error);
      throw new Error(
        `Unable to access SharePoint configuration: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  // Check if vault service is initialized
  isInitialized(): boolean {
    return this.initialized;
  }

  // Get vault status
  getStatus(): { provider: string; initialized: boolean; endpoint: string } {
    return {
      provider: this.vaultProvider,
      initialized: this.initialized,
      endpoint: this.vaultEndpoint,
    };
  }

  // Vault-specific implementations
  // Future use - HashiCorp Vault integration
  // @ts-expect-error - Future implementation
  private async initializeHashiCorpVault(): Promise<void> {
    if (!this.config) {
      throw new Error("Vault configuration not loaded");
    }

    const roleId = this.config.credentials.roleId;
    const secretId = this.config.credentials.secretId;

    if (!roleId || !secretId) {
      throw new Error(
        "HashiCorp Vault credentials not configured. Set VAULT_ROLE_ID and VAULT_SECRET_ID environment variables."
      );
    }

    if (!this.vaultEndpoint || this.vaultEndpoint === "http://localhost:8200") {
      console.warn(
        "⚠️ Using default HashiCorp Vault endpoint. Set VAULT_ADDR environment variable for production."
      );
    }

    try {
      // Authenticate with HashiCorp Vault
      const authResponse = await this.makeVaultRequest(
        "/v1/auth/approle/login",
        {
          method: "POST",
          body: JSON.stringify({
            role_id: roleId,
            secret_id: secretId,
          }),
        }
      );

      const auth = authResponse.auth as { client_token?: string } | undefined;
      if (!auth?.client_token) {
        throw new Error("Invalid authentication response from HashiCorp Vault");
      }

      this.accessToken = auth.client_token;
      // console.log('✅ HashiCorp Vault authentication successful');
    } catch (error) {
      throw new Error(
        `HashiCorp Vault authentication failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  // Future use - AWS Secrets Manager integration
  // @ts-expect-error - Future implementation
  private async initializeAWSSecrets(): Promise<void> {
    if (!this.config) {
      throw new Error("Vault configuration not loaded");
    }

    const region = this.config.credentials.awsRegion;

    if (!this.config.credentials.awsAccessKey) {
      console.warn(
        "⚠️ AWS credentials not configured. Ensure AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are set."
      );
    }

    this.vaultEndpoint = region;
    // console.log(`✅ AWS Secrets Manager initialized for region: ${region}`);

    // Note: Full AWS SDK integration would be implemented here
    // For now, we'll throw an error to indicate it needs implementation
    throw new Error(
      "AWS Secrets Manager integration not fully implemented. Please implement AWS SDK integration."
    );
  }

  // Future use - 1Password Connect integration
  // @ts-expect-error - Future implementation
  private async initialize1Password(): Promise<void> {
    if (!this.config) {
      throw new Error("Vault configuration not loaded");
    }

    this.accessToken = this.config.credentials.opConnectToken;

    if (!this.accessToken) {
      throw new Error(
        "1Password Connect token not configured. Set OP_CONNECT_TOKEN environment variable."
      );
    }

    if (!this.vaultEndpoint) {
      throw new Error(
        "1Password Connect host not configured. Set OP_CONNECT_HOST environment variable."
      );
    }

    try {
      // Test connection to 1Password Connect API
      await this.makeVaultRequest("/v1/health", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
        },
      });

      // console.log('✅ 1Password Connect initialized successfully');
      // console.log('🔍 1Password Connect health check:', response);
    } catch (error) {
      throw new Error(
        `1Password Connect initialization failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  // Future use - Azure Key Vault integration
  // @ts-expect-error - Future implementation
  private async initializeAzureKeyVault(): Promise<void> {
    if (!this.config) {
      throw new Error("Vault configuration not loaded");
    }

    const { azureTenantId, azureClientId, azureClientSecret } =
      this.config.credentials;

    if (!azureTenantId || !azureClientId || !azureClientSecret) {
      throw new Error(
        "Azure Key Vault credentials not configured. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables."
      );
    }

    if (!this.vaultEndpoint) {
      throw new Error(
        "Azure Key Vault URL not configured. Set AZURE_VAULT_URL environment variable."
      );
    }

    // console.log('✅ Azure Key Vault initialized');

    // Note: Full Azure Key Vault SDK integration would be implemented here
    throw new Error(
      "Azure Key Vault integration not fully implemented. Please implement Azure SDK integration."
    );
  }

  // Retrieve secrets from vault (implementation depends on provider)
  // Future use - Generic secret retrieval
  // @ts-expect-error - Future implementation
  private async retrieveSecrets(
    secretPath: string
  ): Promise<Record<string, unknown>> {
    switch (this.vaultProvider) {
      case "hashicorp":
        return await this.getHashiCorpSecret(secretPath);
      case "aws-secrets":
        return await this.getAWSSecret(secretPath);
      case "1password":
        return await this.get1PasswordSecret(secretPath);
      case "1password-cli":
        return await this.get1PasswordSecret(secretPath);
      case "azure-keyvault":
        return await this.getAzureSecret(secretPath);
      default:
        throw new Error(`Unsupported vault provider: ${this.vaultProvider}`);
    }
  }

  private async getHashiCorpSecret(
    path: string
  ): Promise<Record<string, unknown>> {
    if (!this.accessToken) {
      throw new Error("HashiCorp Vault not authenticated");
    }

    try {
      const response = await this.makeVaultRequest(`/v1/secret/data/${path}`, {
        method: "GET",
        headers: {
          "X-Vault-Token": this.accessToken,
        },
      });

      const data = response.data as
        | { data?: Record<string, unknown> }
        | undefined;
      if (!data?.data) {
        throw new Error(`Secret not found at path: ${path}`);
      }

      return data.data;
    } catch (error) {
      throw new Error(
        `Failed to retrieve HashiCorp secret: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  private async getAWSSecret(
    _secretName: string
  ): Promise<Record<string, unknown>> {
    // AWS Secrets Manager implementation would go here
    // console.log(`AWS secret requested: ${secretName}`);
    throw new Error("AWS Secrets Manager integration not implemented");
  }

  private async get1PasswordSecret(
    itemId: string
  ): Promise<Record<string, unknown>> {
    if (!this.config) {
      throw new Error("Vault configuration not loaded");
    }

    // Use either Connect token or Service Account token
    const authToken =
      this.vaultProvider === "1password-cli"
        ? this.config.credentials.opServiceAccountToken
        : this.accessToken;

    if (!authToken) {
      throw new Error("1Password authentication not configured");
    }

    try {
      // Get item by ID or title
      const response = await this.makeVaultRequest(`/items/${itemId}`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${authToken}`,
        },
      });

      const item = response as {
        fields?: Array<{
          id?: string;
          type?: string;
          label?: string;
          value?: string;
        }>;
      };

      if (!item.fields) {
        throw new Error(`No fields found in 1Password item: ${itemId}`);
      }

      // Convert 1Password item fields to key-value pairs
      const secrets: Record<string, unknown> = {};

      for (const field of item.fields) {
        if (field.label && field.value) {
          // Map common field labels to expected keys
          switch (field.label.toLowerCase()) {
            case "username":
            case "email":
              secrets.username = field.value;
              break;
            case "password":
              secrets.password = field.value;
              break;
            case "tenant_url":
            case "url":
            case "website":
              secrets.tenant_url = field.value;
              break;
            case "level1_domains":
              secrets.level1_domains = field.value;
              break;
            case "level2_domains":
              secrets.level2_domains = field.value;
              break;
            case "level3_enabled":
              secrets.level3_enabled = field.value === "true";
              break;
            default:
              // Use the label as the key for other fields
              secrets[field.label.toLowerCase().replace(/\s+/g, "_")] =
                field.value;
          }
        }
      }

      return secrets;
    } catch (error) {
      throw new Error(
        `Failed to retrieve 1Password secret: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  private async getAzureSecret(
    _secretName: string
  ): Promise<Record<string, unknown>> {
    // Azure Key Vault implementation would go here
    // console.log(`Azure secret requested: ${secretName}`);
    throw new Error("Azure Key Vault integration not implemented");
  }

  private async makeVaultRequest(
    path: string,
    options: RequestInit
  ): Promise<Record<string, unknown>> {
    if (!this.vaultEndpoint) {
      throw new Error("Vault endpoint not configured");
    }

    const url = `${this.vaultEndpoint}${path}`;

    try {
      const response = await fetchImpl(url, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Vault request failed: ${response.status} ${response.statusText} - ${errorText}`
        );
      }

      const data = await response.json();
      return data as Record<string, unknown>;
    } catch (error) {
      if (error instanceof TypeError && error.message.includes("fetch")) {
        throw new Error(
          "Network error: Unable to connect to vault server. Check your internet connection and vault URL."
        );
      }
      throw error;
    }
  }

  // Rotate credentials (for production use)
  async rotateCredentials(): Promise<void> {
    if (!this.initialized) {
      throw new Error("Vault service not initialized");
    }

    try {
      // Use IPC to rotate credentials via main process (secure)
      // console.log('🔄 Rotating vault credentials via main process...');

      if (
        typeof window !== "undefined" &&
        window.secureBrowser?.vault?.rotateCredentials
      ) {
        const success = await window.secureBrowser.vault.rotateCredentials();
        if (success) {
          // console.log('✅ Credentials rotated successfully via main process');
          return;
        } else {
          throw new Error("Credential rotation failed in main process");
        }
      }

      // Fallback for development
      // console.log('⚠️ Development mode: credential rotation simulated');
    } catch (error) {
      console.error("❌ Failed to rotate credentials:", error);
      throw new Error(
        `Credential rotation failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }
}

// Create singleton instance for application use
export const vaultService = new VaultService();

// SharePoint credential injection helper (to be called from webview)
export const injectSharePointCredentials = async (
  webview: HTMLElement
): Promise<void> => {
  try {
    if (!vaultService.isInitialized()) {
      await vaultService.initialize();
    }

    // Use Electron's secure API to inject credentials (vault credentials handled in main process)
    if (typeof window !== "undefined" && window.secureBrowser) {
      const webviewId = webview.getAttribute("id") || "default";
      await window.secureBrowser.sharepoint.injectCredentials(webviewId);
      // console.log('✅ SharePoint credentials injected successfully');
    } else {
      throw new Error("Secure browser API not available");
    }
  } catch (error) {
    console.error("❌ Failed to inject SharePoint credentials:", error);
    throw new Error(
      `SharePoint login failed: ${
        error instanceof Error ? error.message : String(error)
      }`
    );
  }
};
