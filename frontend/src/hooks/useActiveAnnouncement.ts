import { useEffect, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, Announcement } from '../api/types';

/**
 * v1.2.4: the one announcement the banner shows, from the authenticated
 * `/user/announcements/active`.
 *
 * `null` means there is nothing live — no pinned notice, and everything else
 * either absent or past its expiry. The banner renders nothing at all in that
 * case rather than an empty box.
 *
 * Cached and invalidatable like the other site hooks: an admin who posts a
 * notice should see the banner appear without a full reload.
 */
const REFRESH_MS = 30_000;

interface ActiveRequest {
  generation: number;
  startedAt: number;
  promise: Promise<Announcement | null>;
}

let cached: ActiveRequest | null = null;
let generation = 0;
const subscribers = new Set<(a: Announcement | null) => void>();

function fetchActive(force = false): ActiveRequest {
  if (force || !cached || Date.now() - cached.startedAt >= REFRESH_MS) {
    const requestGeneration = ++generation;
    cached = {
      generation: requestGeneration,
      startedAt: Date.now(),
      promise: api
        .get<unknown, ApiEnvelope<Announcement | null>>('/user/announcements/active')
        .then((res) => (res.code === 0 ? (res.data ?? null) : null))
        // An unreachable banner is not worth an error toast on every page load.
        .catch(() => null),
    };
  }
  return cached;
}

function deliver(request: ActiveRequest, one?: (a: Announcement | null) => void) {
  request.promise.then((announcement) => {
    // A forced refresh may have started while this request was in flight. Never
    // let the older response overwrite the newer announcement.
    if (request.generation !== generation) return;
    if (one) one(announcement);
    else subscribers.forEach((fn) => fn(announcement));
  });
}

function refreshActive() {
  deliver(fetchActive(true));
}

/** Drop the cache; re-fetch only if something is currently displaying it. */
export function invalidateActiveAnnouncement() {
  cached = null;
  generation += 1;
  if (subscribers.size === 0) return;
  refreshActive();
}

export function useActiveAnnouncement(): Announcement | null {
  const [active, setActive] = useState<Announcement | null>(null);
  useEffect(() => {
    let alive = true;
    const update = (a: Announcement | null) => { if (alive) setActive(a); };
    subscribers.add(update);
    deliver(fetchActive(), update);
    const interval = window.setInterval(refreshActive, REFRESH_MS);
    window.addEventListener('focus', refreshActive);
    return () => {
      alive = false;
      subscribers.delete(update);
      window.clearInterval(interval);
      window.removeEventListener('focus', refreshActive);
    };
  }, []);
  return active;
}
