import { useContext } from 'react';
import { SiteConfigContext } from './context';

export function useSiteConfig() {
  return useContext(SiteConfigContext);
}
