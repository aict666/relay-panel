import { createContext } from 'react';

export const DEFAULT_SITE_NAME = 'RelayPanel';

export interface SiteConfigContextValue {
  siteName: string;
  setSiteName: (siteName: string) => void;
}

export const SiteConfigContext = createContext<SiteConfigContextValue>({
  siteName: DEFAULT_SITE_NAME,
  setSiteName: () => {},
});
