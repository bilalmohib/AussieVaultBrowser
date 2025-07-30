// Using direct fetch approach instead of MSAL library for now
// This will work with existing environment variables

export interface SharePointFile {
  id: string;
  name: string;
  size?: number;
  lastModified?: string;
  webUrl?: string;
  downloadUrl?: string;
  isFolder: boolean;
  type: 'file' | 'folder';
  mimeType?: string;
  parentId?: string;
}

export interface SharePointSite {
  id: string;
  name: string;
  webUrl: string;
  description?: string;
  drives?: SharePointDrive[];
}

export interface SharePointDrive {
  id: string;
  name: string;
  driveType: string;
  webUrl?: string;
}

export interface BreadcrumbItem {
  id: string | null;
  name: string;
}

export class SharePointService {
  private static instance: SharePointService;
  private currentToken: string | null = null;
  private tokenExpiry: Date | null = null;
  private initialized = false;

  private constructor() {}

  public static getInstance(): SharePointService {
    if (!SharePointService.instance) {
      SharePointService.instance = new SharePointService();
    }
    return SharePointService.instance;
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Get environment variables through the Electron bridge
      let envVars: any = {};
      
      if (typeof window !== 'undefined' && window.secureBrowser?.system?.getEnvironment) {
        const envString = await window.secureBrowser.system.getEnvironment();
        envVars = JSON.parse(envString);
      } else {
        throw new Error('Unable to access environment variables. Make sure you are running in Electron context.');
      }

      // Check if we have the required MSAL environment variables
      const clientId = envVars.MSAL_CLIENT_ID;
      const tenantId = envVars.MSAL_TENANT_ID;
      const clientSecret = envVars.MSAL_CLIENT_SECRET;

      if (!clientId || !tenantId || !clientSecret) {
        throw new Error('MSAL configuration missing. Please check MSAL_CLIENT_ID, MSAL_TENANT_ID, and MSAL_CLIENT_SECRET in environment variables.');
      }

      this.initialized = true;
      
      console.log('✅ SharePoint service initialized successfully');
      console.log('📧 Client ID:', clientId.substring(0, 8) + '...');
      console.log('🏢 Tenant ID:', tenantId.substring(0, 8) + '...');
    } catch (error) {
      console.error('❌ Failed to initialize SharePoint service:', error);
      throw new Error(`SharePoint initialization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async getAccessToken(): Promise<string> {
    if (!this.initialized) {
      throw new Error('SharePoint service not initialized');
    }

    // Check if we have a valid token
    if (this.currentToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return this.currentToken;
    }

    try {
      console.log('🔄 Acquiring new access token via main process...');
      
      // Use main process to handle OAuth (bypasses CORS)
      if (typeof window !== 'undefined' && window.secureBrowser?.sharepoint?.getOAuthToken) {
        const result = await window.secureBrowser.sharepoint.getOAuthToken();
        
        if (result.success && result.accessToken) {
          this.currentToken = result.accessToken;
          // Set expiry to 55 minutes from now (tokens usually last 1 hour)
          this.tokenExpiry = new Date(Date.now() + (55 * 60 * 1000));
          
          console.log('✅ Access token acquired successfully via main process');
          console.log(`📅 Token expires at: ${this.tokenExpiry.toISOString()}`);
          
          return this.currentToken;
        } else {
          throw new Error(result.error || 'Failed to get OAuth token from main process');
        }
      } else {
        throw new Error('Main process OAuth handler not available');
      }
    } catch (error) {
      console.error('❌ Error acquiring access token:', error);
      throw new Error(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getSites(): Promise<SharePointSite[]> {
    try {
      const token = await this.getAccessToken();
      let discoveredSite: SharePointSite | null = null;

      console.log('🔍 Starting SharePoint site discovery...');

      // Try SharePoint root site first
      try {
        const rootResponse = await window.secureBrowser.sharepoint.graphRequest('/sites/root', token);

        if (rootResponse.success && rootResponse.data) {
          const rootData = rootResponse.data;
          console.log('✅ SharePoint root site accessible!');
          
          discoveredSite = {
            id: rootData.id,
            name: rootData.displayName || 'SharePoint Root Site',
            webUrl: rootData.webUrl,
            description: rootData.description || 'SharePoint Root Site',
          };
        }
      } catch (error) {
        console.log('Root site discovery failed, trying hostname approach...');
      }

      // Try hostname-based approach if root failed
      if (!discoveredSite) {
        // Get SharePoint base URL from environment
        let sharepointBaseUrl = '';
        try {
          if (typeof window !== 'undefined' && window.secureBrowser?.system?.getEnvironment) {
            const envString = await window.secureBrowser.system.getEnvironment();
            const envVars = JSON.parse(envString);
            sharepointBaseUrl = envVars.SHAREPOINT_BASE_URL || '';
          }
        } catch (error) {
          console.warn('Failed to get SHAREPOINT_BASE_URL from environment:', error);
        }
        
        if (sharepointBaseUrl) {
          try {
            const hostname = sharepointBaseUrl.replace('.sharepoint.com', '');
            const hostnameResponse = await window.secureBrowser.sharepoint.graphRequest(
              `/sites/${hostname}.sharepoint.com`,
              token
            );

            if (hostnameResponse.success && hostnameResponse.data) {
              const hostnameData = hostnameResponse.data;
              console.log('✅ SharePoint site accessible via hostname!');
              
              discoveredSite = {
                id: hostnameData.id,
                name: hostnameData.displayName || sharepointBaseUrl,
                webUrl: hostnameData.webUrl,
                description: hostnameData.description || 'SharePoint Site',
              };
            }
          } catch (error) {
            console.log('Hostname method failed:', error);
          }
        }
      }

      if (!discoveredSite) {
        throw new Error('Unable to discover SharePoint site. Please check your configuration.');
      }

      // Get drives for the discovered site
      discoveredSite.drives = await this.getSiteDrives(discoveredSite.id);

      return [discoveredSite];
    } catch (error) {
      console.error('❌ Error getting SharePoint sites:', error);
      throw new Error(`Failed to get SharePoint sites: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getSiteDrives(siteId: string): Promise<SharePointDrive[]> {
    try {
      const token = await this.getAccessToken();
      
      const response = await window.secureBrowser.sharepoint.graphRequest(
        `/sites/${siteId}/drives`,
        token
      );

      if (response.success && response.data) {
        return response.data.value || [];
      } else {
        throw new Error(response.error || 'Failed to get site drives');
      }
    } catch (error) {
      console.error('❌ Error getting site drives:', error);
      throw new Error(`Failed to get site drives: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getFiles(siteId: string, driveId: string, folderId?: string): Promise<SharePointFile[]> {
    try {
      const token = await this.getAccessToken();
      
      let endpoint: string;
      if (folderId) {
        endpoint = `/sites/${siteId}/drives/${driveId}/items/${folderId}/children`;
      } else {
        endpoint = `/sites/${siteId}/drives/${driveId}/root/children`;
      }

      const response = await window.secureBrowser.sharepoint.graphRequest(endpoint, token);

      if (response.success && response.data) {
        return (response.data.value || []).map((item: any): SharePointFile => ({
          id: item.id,
          name: item.name,
          size: item.size,
          lastModified: item.lastModifiedDateTime,
          webUrl: item.webUrl,
          downloadUrl: item['@microsoft.graph.downloadUrl'],
          isFolder: !!item.folder,
          type: item.folder ? 'folder' : 'file',
          mimeType: item.file?.mimeType,
          parentId: folderId || 'root',
        }));
      } else {
        throw new Error(response.error || 'Failed to get files');
      }
    } catch (error) {
      console.error('❌ Error getting files:', error);
      throw new Error(`Failed to get files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async downloadFile(downloadUrl: string): Promise<Blob> {
    try {
      // Download URLs from Graph API usually don't need authorization
      // They contain a temporary access token in the URL
      const response = await fetch(downloadUrl);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.blob();
    } catch (error) {
      console.error('❌ Error downloading file:', error);
      throw new Error(`Failed to download file: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  getFileIcon(file: SharePointFile): string {
    if (file.isFolder) return '📁';
    
    const extension = file.name.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'pdf': return '📕';
      case 'doc':
      case 'docx': return '📘';
      case 'xls':
      case 'xlsx': return '📗';
      case 'ppt':
      case 'pptx': return '📙';
      case 'jpg':
      case 'jpeg':
      case 'png':
      case 'gif':
      case 'bmp': return '🖼️';
      case 'mp4':
      case 'avi':
      case 'mov': return '🎬';
      case 'mp3':
      case 'wav':
      case 'flac': return '🎵';
      case 'zip':
      case 'rar':
      case '7z': return '📦';
      case 'txt': return '📄';
      default: return '📄';
    }
  }

  formatFileSize(bytes?: number): string {
    if (!bytes) return 'Unknown';
    
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${Math.round(bytes / Math.pow(1024, i) * 100) / 100} ${sizes[i]}`;
  }

  formatDate(dateString?: string): string {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    if (days === 0) return 'Today';
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days} days ago`;
    if (days < 30) return `${Math.floor(days / 7)} weeks ago`;
    if (days < 365) return `${Math.floor(days / 30)} months ago`;
    
    return date.toLocaleDateString();
  }

  isServiceInitialized(): boolean {
    return this.initialized;
  }
}

export const sharepointService = SharePointService.getInstance();