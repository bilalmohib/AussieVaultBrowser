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
      
      // console.log('✅ SharePoint service initialized successfully');
      // console.log('📧 Client ID:', clientId.substring(0, 8) + '...');
      // console.log('🏢 Tenant ID:', tenantId.substring(0, 8) + '...');
    } catch (error) {
      // console.error('❌ Failed to initialize SharePoint service:', error);
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
      console.log('🔍 Checking secureBrowser API availability:', {
        hasWindow: typeof window !== 'undefined',
        hasSecureBrowser: !!window?.secureBrowser,
        hasSharepoint: !!window?.secureBrowser?.sharepoint,
        hasGetOAuthToken: !!window?.secureBrowser?.sharepoint?.getOAuthToken
      });
      
      // Use main process to handle OAuth (bypasses CORS)
      if (typeof window !== 'undefined' && window.secureBrowser?.sharepoint?.getOAuthToken) {
        console.log('📞 Calling main process for OAuth token...');
        const result = await window.secureBrowser.sharepoint.getOAuthToken();
        
        console.log('📡 OAuth result:', { success: result.success, hasToken: !!result.accessToken, error: result.error });
        
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
        console.error('❌ Main process OAuth handler not available');
        console.log('🔍 Available APIs:', Object.keys(window?.secureBrowser || {}));
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

      // console.log('🔍 Starting SharePoint site discovery...');

      // Try SharePoint root site first
      try {
        const rootResponse = await window.secureBrowser.sharepoint.graphRequest('/sites/root', token);

        if (rootResponse.success && rootResponse.data) {
          const rootData = rootResponse.data;
          // console.log('✅ SharePoint root site accessible!');
          
          discoveredSite = {
            id: rootData.id,
            name: rootData.displayName || 'SharePoint Root Site',
            webUrl: rootData.webUrl,
            description: rootData.description || 'SharePoint Root Site',
          };
        }
      } catch (error) {
        // console.log('Root site discovery failed, trying hostname approach...');
      }

      // Try hostname-based approach if root failed
      if (!discoveredSite) {
        // Get SharePoint base URL from environment
        let sharepointBaseUrl = '';
        try {
          // Use the config-manager to get the SharePoint base URL
          // This will check both environment_variables and system_settings as appropriate
          const { getConfig } = await import('../utils/config-manager');
          sharepointBaseUrl = await getConfig('SHAREPOINT_BASE_URL', '');
          
          if (!sharepointBaseUrl) {
            // Fallback to direct environment access if config-manager fails
            if (typeof window !== 'undefined' && window.secureBrowser?.system?.getEnvironment) {
              const envString = await window.secureBrowser.system.getEnvironment();
              const envVars = JSON.parse(envString);
              sharepointBaseUrl = envVars.SHAREPOINT_BASE_URL || '';
            }
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
              // console.log('✅ SharePoint site accessible via hostname!');
              
              discoveredSite = {
                id: hostnameData.id,
                name: hostnameData.displayName || sharepointBaseUrl,
                webUrl: hostnameData.webUrl,
                description: hostnameData.description || 'SharePoint Site',
              };
            }
          } catch (error) {
            // console.log('Hostname method failed:', error);
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
      // console.error('❌ Error getting SharePoint sites:', error);
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
      // console.error('❌ Error getting site drives:', error);
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
      // console.error('❌ Error getting files:', error);
      throw new Error(`Failed to get files: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async downloadFile(downloadUrl: string): Promise<Blob> {
    try {
      console.log('🔄 Downloading file from:', downloadUrl.substring(0, 50) + '...');
      
      // ENHANCED: Use proper headers for binary file download
      const response = await fetch(downloadUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/octet-stream',
          'Cache-Control': 'no-cache'
        },
        credentials: 'include',
        cache: 'no-store'
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const blob = await response.blob();
      console.log(`✅ File downloaded successfully: ${blob.size} bytes, type: ${blob.type || 'application/octet-stream'}`);
      
      // Ensure blob has content
      if (blob.size === 0) {
        throw new Error('Downloaded file is empty (0 bytes)');
      }
      
      return blob;
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

  /**
   * Get the appropriate MIME type for a file based on its extension
   * This is used for drag-and-drop and downloads
   */
  getMimeType(fileName: string): string {
    const extension = fileName.split('.').pop()?.toLowerCase() || '';
    
    // Document types
    if (extension === 'pdf') return 'application/pdf';
    if (extension === 'doc') return 'application/msword';
    if (extension === 'docx') return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    if (extension === 'xls') return 'application/vnd.ms-excel';
    if (extension === 'xlsx') return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    if (extension === 'ppt') return 'application/vnd.ms-powerpoint';
    if (extension === 'pptx') return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
    if (extension === 'txt') return 'text/plain';
    
    // Image types
    if (extension === 'jpg' || extension === 'jpeg') return 'image/jpeg';
    if (extension === 'png') return 'image/png';
    if (extension === 'gif') return 'image/gif';
    if (extension === 'bmp') return 'image/bmp';
    if (extension === 'svg') return 'image/svg+xml';
    if (extension === 'webp') return 'image/webp';
    
    // Video types
    if (['mp4', 'avi', 'mov', 'mkv', 'wmv'].includes(extension)) {
      return extension === 'mp4' ? 'video/mp4' : 
             extension === 'avi' ? 'video/x-msvideo' :
             extension === 'mov' ? 'video/quicktime' :
             extension === 'mkv' ? 'video/x-matroska' :
             'video/x-ms-wmv';
    }
    
    // Audio types
    if (['mp3', 'wav', 'ogg', 'flac'].includes(extension)) {
      return extension === 'mp3' ? 'audio/mpeg' :
             extension === 'wav' ? 'audio/wav' :
             extension === 'ogg' ? 'audio/ogg' :
             'audio/flac';
    }
    
    // Archive types
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(extension)) {
      return extension === 'zip' ? 'application/zip' :
             extension === 'rar' ? 'application/vnd.rar' :
             extension === '7z' ? 'application/x-7z-compressed' :
             extension === 'tar' ? 'application/x-tar' :
             'application/gzip';
    }
    
    // Web types
    if (extension === 'html' || extension === 'htm') return 'text/html';
    if (extension === 'css') return 'text/css';
    if (extension === 'js') return 'application/javascript';
    if (extension === 'json') return 'application/json';
    
    // Default fallback
    return 'application/octet-stream';
  }
}

export const sharepointService = SharePointService.getInstance();