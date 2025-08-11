import { supabase } from "@/lib/supabase";

export interface Bookmark {
  id?: number;
  url: string;
  title: string;
  description?: string;
  favicon_url?: string;
  folder_name: string;
  tags: string[];
  is_public: boolean;
  access_level: number;
  device_id?: string;
  created_at?: string;
  updated_at?: string;
  user_id?: number;
}

export class BookmarksService {
  private static instance: BookmarksService;

  public static getInstance(): BookmarksService {
    if (!BookmarksService.instance) {
      BookmarksService.instance = new BookmarksService();
    }
    return BookmarksService.instance;
  }

  // Check if a URL is bookmarked
  async isBookmarked(url: string, userId: number): Promise<boolean> {
    try {
      // DISABLE bookmark checking entirely in development to prevent 406 errors
      if (window.location.hostname === "localhost") {
        return false;
      }

      // Skip bookmark check for problematic URLs to prevent 406 errors
      if (
        !url ||
        url.length > 800 ||
        url.includes("google.com") ||
        url.includes("search?q=") ||
        url.includes("sca_esv=") ||
        url.includes("&ved=") ||
        url.includes("&ei=") ||
        url.includes("&iflsig=") ||
        url.includes("&oq=") ||
        url.includes("&gs_lp=")
      ) {
        // console.log('⚠️ Skipping bookmark check for problematic URL');
        return false;
      }

      // console.log('🔍 Checking bookmark status:', { url, userId });

      const { data, error } = await supabase
        .from("bookmarks")
        .select("id")
        .eq("user_id", userId)
        .eq("url", url)
        .single();

      if (error && error.code !== "PGRST116") {
        // PGRST116 is "not found" error
        // console.error('❌ Error checking bookmark status:', error);
        return false;
      }

      const isBookmarked = !!data;
      // console.log('✅ Bookmark status checked:', { url, userId, isBookmarked });
      return isBookmarked;
    } catch (error) {
      // console.error('❌ Error checking bookmark status:', error);
      return false;
    }
  }

  // Add a bookmark
  async addBookmark(bookmark: Bookmark, userId: number): Promise<boolean> {
    try {
      // console.log('📌 Adding bookmark:', { bookmark, userId });

      // Check if bookmark already exists
      const exists = await this.isBookmarked(bookmark.url, userId);
      if (exists) {
        // console.log('✅ Bookmark already exists');
        return true;
      }

      const bookmarkData = {
        user_id: userId,
        url: bookmark.url,
        title: bookmark.title,
        description: bookmark.description,
        favicon_url: bookmark.favicon_url,
        folder_name: bookmark.folder_name || "General",
        tags: bookmark.tags || [],
        is_public: bookmark.is_public || false,
        access_level: bookmark.access_level,
        device_id: bookmark.device_id,
      };

      // console.log('📌 Inserting bookmark data:', bookmarkData);

      const { data: _data, error } = await supabase
        .from("bookmarks")
        .insert(bookmarkData)
        .select()
        .single();

      if (error) {
        // console.error('❌ Error adding bookmark:', error);
        // console.error('❌ Error details:', {
        //   code: error.code,
        //   message: error.message,
        //   details: error.details,
        //   hint: error.hint
        // });
        return false;
      }

      // console.log('✅ Bookmark added successfully:', data);
      return true;
    } catch (error) {
      // console.error('❌ Error adding bookmark:', error);
      return false;
    }
  }

  // Remove a bookmark
  async removeBookmark(url: string, userId: number): Promise<boolean> {
    try {
      const { error } = await supabase
        .from("bookmarks")
        .delete()
        .eq("user_id", userId)
        .eq("url", url);

      if (error) {
        // console.error('Error removing bookmark:', error);
        return false;
      }

      // console.log('✅ Bookmark removed successfully');
      return true;
    } catch (error) {
      // console.error('Error removing bookmark:', error);
      return false;
    }
  }

  // Get all bookmarks for a user
  async getUserBookmarks(userId: number): Promise<Bookmark[]> {
    try {
      const { data, error } = await supabase
        .from("bookmarks")
        .select("*")
        .eq("user_id", userId)
        .order("created_at", { ascending: false });

      if (error) {
        // console.error('Error fetching user bookmarks:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      // console.error('Error fetching user bookmarks:', error);
      return [];
    }
  }

  // Get unique folders for a user
  async getUserFolders(userId: number): Promise<string[]> {
    try {
      const { data, error } = await supabase
        .from("bookmarks")
        .select("folder_name")
        .eq("user_id", userId)
        .not("folder_name", "is", null);

      if (error) {
        // console.error('Error fetching user folders:', error);
        return [];
      }

      const folders = [
        ...new Set(data?.map((item) => item.folder_name).filter(Boolean) || []),
      ];
      return folders.sort();
    } catch (error) {
      // console.error('Error fetching user folders:', error);
      return [];
    }
  }

  // Search bookmarks
  async searchBookmarks(
    userId: number,
    searchTerm: string,
    folderId?: string
  ): Promise<Bookmark[]> {
    try {
      let query = supabase.from("bookmarks").select("*").eq("user_id", userId);

      // Add folder filter if provided
      if (folderId && folderId !== "all") {
        query = query.eq("folder_name", folderId);
      }

      // Add search filter
      if (searchTerm) {
        query = query.or(
          `title.ilike.%${searchTerm}%,url.ilike.%${searchTerm}%,description.ilike.%${searchTerm}%`
        );
      }

      const { data, error } = await query.order("created_at", {
        ascending: false,
      });

      if (error) {
        // console.error('Error searching bookmarks:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      // console.error('Error searching bookmarks:', error);
      return [];
    }
  }

  // Get bookmarks by folder
  async getBookmarksByFolder(
    userId: number,
    folderName: string
  ): Promise<Bookmark[]> {
    try {
      const { data, error } = await supabase
        .from("bookmarks")
        .select("*")
        .eq("user_id", userId)
        .eq("folder_name", folderName)
        .order("created_at", { ascending: false });

      if (error) {
        // console.error('Error fetching bookmarks by folder:', error);
        return [];
      }

      return data || [];
    } catch (error) {
      // console.error('Error fetching bookmarks by folder:', error);
      return [];
    }
  }

  // Update bookmark
  async updateBookmark(
    bookmarkId: number,
    updates: Partial<Bookmark>,
    userId: number
  ): Promise<boolean> {
    try {
      const { error } = await supabase
        .from("bookmarks")
        .update(updates)
        .eq("id", bookmarkId)
        .eq("user_id", userId);

      if (error) {
        // console.error('Error updating bookmark:', error);
        return false;
      }

      // console.log('✅ Bookmark updated successfully');
      return true;
    } catch (error) {
      // console.error('Error updating bookmark:', error);
      return false;
    }
  }

  // Get bookmark statistics
  async getBookmarkStats(userId: number): Promise<{
    total: number;
    folders: number;
    public: number;
    private: number;
  }> {
    try {
      // Get total count
      const { count: total } = await supabase
        .from("bookmarks")
        .select("*", { count: "exact", head: true })
        .eq("user_id", userId);

      // Get folder count
      const { data: folderData } = await supabase
        .from("bookmarks")
        .select("folder_name")
        .eq("user_id", userId);

      const folders = new Set(
        folderData?.map((b) => b.folder_name).filter(Boolean)
      ).size;

      // Get public/private counts
      const { count: publicCount } = await supabase
        .from("bookmarks")
        .select("*", { count: "exact", head: true })
        .eq("user_id", userId)
        .eq("is_public", true);

      return {
        total: total || 0,
        folders: folders || 0,
        public: publicCount || 0,
        private: (total || 0) - (publicCount || 0),
      };
    } catch (error) {
      // console.error('Error getting bookmark stats:', error);
      return { total: 0, folders: 0, public: 0, private: 0 };
    }
  }

  // Toggle bookmark status
  async toggleBookmark(
    url: string,
    title: string,
    userId: number,
    accessLevel: number
  ): Promise<boolean> {
    // console.log('🔄 Toggle bookmark called:', { url, title, userId, accessLevel });

    try {
      const isCurrentlyBookmarked = await this.isBookmarked(url, userId);
      // console.log('📊 Current bookmark status:', isCurrentlyBookmarked);

      if (isCurrentlyBookmarked) {
        // console.log('🗑️ Removing existing bookmark...');
        return await this.removeBookmark(url, userId);
      } else {
        // console.log('➕ Adding new bookmark...');
        const bookmark: Bookmark = {
          url,
          title,
          folder_name: "General",
          tags: [],
          is_public: false,
          access_level: accessLevel,
        };
        return await this.addBookmark(bookmark, userId);
      }
    } catch (error) {
      // console.error('❌ Error in toggleBookmark:', error);
      return false;
    }
  }

  // Export bookmarks to JSON
  async exportBookmarks(userId: number): Promise<Bookmark[]> {
    return await this.getUserBookmarks(userId);
  }

  // Import bookmarks from JSON
  async importBookmarks(
    bookmarks: Bookmark[],
    userId: number
  ): Promise<{ success: number; failed: number }> {
    let success = 0;
    let failed = 0;

    for (const bookmark of bookmarks) {
      const result = await this.addBookmark(bookmark, userId);
      if (result) {
        success++;
      } else {
        failed++;
      }
    }

    return { success, failed };
  }
}
