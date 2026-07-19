import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import api from '../api/client';
import type { ApiEnvelope, RegistrationStatus } from '../api/types';
import { DEFAULT_SITE_NAME, SiteConfigContext } from './context';

export function SiteConfigProvider({ children }: { children: ReactNode }) {
  const [siteName, setSiteNameState] = useState(DEFAULT_SITE_NAME);

  const setSiteName = useCallback((value: string) => {
    const normalized = value.trim();
    setSiteNameState(normalized || DEFAULT_SITE_NAME);
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .get<unknown, ApiEnvelope<RegistrationStatus>>('/auth/registration-status')
      .then((response) => {
        if (!cancelled && response.data?.site_name) {
          setSiteName(response.data.site_name);
        }
      })
      .catch(() => {
        // Keep the built-in name when the public settings probe is unavailable.
      });
    return () => {
      cancelled = true;
    };
  }, [setSiteName]);

  useEffect(() => {
    document.title = siteName;
  }, [siteName]);

  const value = useMemo(() => ({ siteName, setSiteName }), [siteName, setSiteName]);
  return <SiteConfigContext.Provider value={value}>{children}</SiteConfigContext.Provider>;
}
