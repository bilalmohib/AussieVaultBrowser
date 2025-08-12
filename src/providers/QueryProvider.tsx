"use client"

import React from 'react'
import { QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
// import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { toast } from 'sonner'

import { DatabaseService, RealtimeService, type UserSession } from '@/lib/supabase'

interface QueryProviderProps {
  children: React.ReactNode
}

export function QueryProvider({ children }: QueryProviderProps) {
  const [queryClient] = React.useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 1000 * 60 * 5, // 5 minutes
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          // Don't retry on 4xx errors
          if (error && typeof error === 'object' && 'status' in error) {
            const status = (error as any).status
            if (status >= 400 && status < 500) {
              return false
            }
          }
          // Retry up to 3 times for other errors
          return failureCount < 3
        },
      },
      mutations: {
        retry: 1,
        onError: (error) => {
          console.error('Mutation error:', error)
          toast.error('An error occurred. Please try again.')
        },
      },
    },
  }))

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {/* Devtools disabled for faster startup */}
    </QueryClientProvider>
  )
}

// Custom hooks for database operations
export function useCurrentUser(email: string | null) {
  return useQuery({
    queryKey: ['currentUser', email],
    queryFn: () => email ? DatabaseService.getCurrentUser(email) : null,
    enabled: !!email,
    staleTime: 1000 * 60 * 10, // 10 minutes
  })
}

export function useCreateUserSession() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: DatabaseService.createUserSession,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['userSessions'] })
      toast.success('Session created successfully')
    },
    onError: (error: any) => {
      console.error('Failed to create session:', error)
      toast.error('Failed to create session')
    },
  })
}

export function useUpdateUserSession() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ sessionId, updates }: { sessionId: number, updates: Partial<UserSession> }) =>
      DatabaseService.updateUserSession(sessionId, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['userSessions'] })
    },
  })
}

export function useLogSecurityEvent() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: DatabaseService.logSecurityEvent,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['securityEvents'] })
    },
  })
}

export function useLogNavigation() {
  return useMutation({
    mutationFn: DatabaseService.logNavigation,
    onError: (error: any) => {
      console.error('Failed to log navigation:', error)
    },
  })
}

export function useLogVPNConnection() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: DatabaseService.logVPNConnection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpnConnections'] })
      toast.success('VPN connection logged')
    },
  })
}

export function useAccessLevel(level: number) {
  return useQuery({
    queryKey: ['accessLevel', level],
    queryFn: () => DatabaseService.getAccessLevel(level),
    staleTime: 1000 * 60 * 30, // 30 minutes
  })
}

export function useSystemSettings(category?: string) {
  return useQuery({
    queryKey: ['systemSettings', category],
    queryFn: () => DatabaseService.getSystemSettings(category),
    staleTime: 1000 * 60 * 15, // 15 minutes
  })
}

// Real-time hooks
export function useUserSessionsRealtime(userId: number) {
  const queryClient = useQueryClient()
  
  React.useEffect(() => {
    if (!userId) return
    
    const subscription = RealtimeService.subscribeToUserSessions(userId, (_payload) => {
      queryClient.invalidateQueries({ queryKey: ['userSessions', userId] })
    })
    
    return () => {
      subscription.unsubscribe().catch(console.error)
    }
  }, [userId, queryClient])
}

export function useSecurityEventsRealtime() {
  const queryClient = useQueryClient()
  
  React.useEffect(() => {
    const subscription = RealtimeService.subscribeToSecurityEvents((payload) => {
      queryClient.invalidateQueries({ queryKey: ['securityEvents'] })
      
      // Show toast for critical security events
      if (payload.new && payload.new.severity === 'critical') {
        toast.error(`Security Alert: ${payload.new.description}`)
      }
    })
    
    return () => {
      subscription.unsubscribe().catch(console.error)
    }
  }, [queryClient])
}

export function useVPNConnectionsRealtime(userId: number) {
  const queryClient = useQueryClient()
  
  React.useEffect(() => {
    if (!userId) return
    
    const subscription = RealtimeService.subscribeToVPNConnections(userId, (_payload) => {
      queryClient.invalidateQueries({ queryKey: ['vpnConnections', userId] })
    })
    
    return () => {
      subscription.unsubscribe().catch(console.error)
    }
  }, [userId, queryClient])
}

// Helper hooks for combining multiple queries
export function useUserDashboardData(_userId: number, email: string) {
  const userQuery = useCurrentUser(email)
  const accessLevelQuery = useAccessLevel(userQuery.data?.access_level || 1)
  
  return {
    user: userQuery.data,
    accessLevel: accessLevelQuery.data,
    isLoading: userQuery.isLoading || accessLevelQuery.isLoading,
    error: userQuery.error || accessLevelQuery.error,
  }
} 