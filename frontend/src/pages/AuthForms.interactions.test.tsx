import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, post: mockPost },
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ login: vi.fn() }),
}));

import Login from './Login';
import Register from './Register';

const registrationStatus = {
  code: 0,
  message: 'ok',
  data: {
    enabled: true,
    default_plan_id: 1,
    plans: [],
    site_name: 'RelayPanel',
    default_password_change_required: false,
  },
};

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockGet.mockResolvedValue(registrationStatus);
  mockPost.mockImplementation(() => new Promise(() => {}));
});

describe('authentication form submission locks', () => {
  it('sends only one login request when the form submits twice in one render frame', async () => {
    const { container } = render(<MemoryRouter><Login /></MemoryRouter>);
    fireEvent.change(screen.getByRole('textbox', { name: 'username' }), { target: { value: 'member' } });
    fireEvent.change(screen.getByLabelText('password'), { target: { value: 'password123' } });

    const form = container.querySelector('form')!;
    fireEvent.submit(form);
    fireEvent.submit(form);

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
  });

  it('sends only one registration request when the form submits twice in one render frame', async () => {
    const { container } = render(<MemoryRouter><Register /></MemoryRouter>);
    await screen.findByRole('button', { name: 'register' });
    fireEvent.change(screen.getByRole('textbox', { name: 'username' }), { target: { value: 'member' } });
    const passwordInputs = screen.getAllByLabelText(/password|confirmPassword/);
    fireEvent.change(passwordInputs[0], { target: { value: 'password123' } });
    fireEvent.change(passwordInputs[1], { target: { value: 'password123' } });

    const form = container.querySelector('form')!;
    fireEvent.submit(form);
    fireEvent.submit(form);

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
  });
});
