import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { NodeDisplayRow } from '../../api/types';

// NodeDetailDrawer calls api.delete on the admin "delete status" action, so the
// client must be mocked before importing the component.
vi.mock('../../api/client', () => ({
  default: { delete: vi.fn().mockResolvedValue({ code: 0 }) },
}));

import { NodeDetailDrawer } from './NodeDetailDrawer';

const baseRow: NodeDisplayRow = {
  group_id: 1,
  group_name: 'g1',
  node_id: 'node-abc',
  online: true,
  cpu: 10,
  mem: 20,
  network_interface: 'eth0',
  config_protocol_version: 2,
};

describe('NodeDetailDrawer desensitization', () => {
  it('shows admin-only sensitive fields when isAdmin is true', () => {
    render(<NodeDetailDrawer row={baseRow} open onClose={vi.fn()} isAdmin={true} panelProtocol={2} />);
    // node_id value + admin-only labels are present
    expect(screen.getByText('node-abc')).toBeInTheDocument();
    expect(screen.getByText('configProtocolVersion')).toBeInTheDocument();
    expect(screen.getByText('networkInterface')).toBeInTheDocument();
    // Online nodes cannot be manually removed from either admin entry point.
    expect(screen.queryByText('nodeStatusDelete')).not.toBeInTheDocument();
  });

  it('shows cleanup to an administrator only after the node is offline', () => {
    render(<NodeDetailDrawer row={{ ...baseRow, online: false }} open onClose={vi.fn()} isAdmin panelProtocol={2} />);
    expect(screen.getByText('nodeStatusDelete')).toBeInTheDocument();
  });

  it('hides node_id and all admin-only fields when isAdmin is false', () => {
    render(<NodeDetailDrawer row={baseRow} open onClose={vi.fn()} isAdmin={false} panelProtocol={2} />);
    // the raw node_id must never reach a regular user's DOM
    expect(screen.queryByText('node-abc')).not.toBeInTheDocument();
    expect(screen.queryByText('configProtocolVersion')).not.toBeInTheDocument();
    expect(screen.queryByText('networkInterface')).not.toBeInTheDocument();
    expect(screen.queryByText('nodeStatusDelete')).not.toBeInTheDocument();
    // safe metrics are still rendered (sanity: the drawer did open)
    expect(screen.getByText('nodeVersion')).toBeInTheDocument();
  });
});
