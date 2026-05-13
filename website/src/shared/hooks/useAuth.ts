import { createContext, useContext } from 'react';

export interface AuthState {
  loading: boolean;
  isAuthenticated: boolean;
}

export const AuthContext = createContext<AuthState>({
  loading: true,
  isAuthenticated: false,
});

export function useAuth() {
  return useContext(AuthContext);
}
