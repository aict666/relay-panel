import { AxiosHeaders, type AxiosAdapter } from 'axios';
import { describe, expect, it } from 'vitest';
import api from './client';

function responseAdapter(data: unknown): AxiosAdapter {
  return async (config) => ({
    data,
    status: 200,
    statusText: 'OK',
    headers: new AxiosHeaders(),
    config,
  });
}

describe('API business envelopes', () => {
  it('rejects server-error envelopes even when HTTP status is 200', async () => {
    const request = api.get('/probe', {
      adapter: responseAdapter({ code: 500, message: '数据库错误', data: null }),
    });

    await expect(request).rejects.toMatchObject({
      message: '数据库错误',
      response: { data: { code: 500, message: '数据库错误', data: null } },
    });
  });

  it('keeps validation and conflict envelopes available to callers', async () => {
    const response = await api.get('/probe', {
      adapter: responseAdapter({ code: 409, message: '名称已存在', data: null }),
    });

    expect(response).toEqual({ code: 409, message: '名称已存在', data: null });
  });
});
