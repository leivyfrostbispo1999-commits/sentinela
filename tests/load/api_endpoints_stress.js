import http from 'k6/http';
import ws from 'k6/ws';
import { check, group, sleep } from 'k6';
import { BASE_URL, SLEEP_SECONDS } from './common.js';

const USERNAME = __ENV.USERNAME || 'admin';
const PASSWORD = __ENV.PASSWORD || 'sentinela';
const WS_URL = (__ENV.WS_URL || BASE_URL.replace('http://', 'ws://').replace('https://', 'wss://')) + '/ws/alerts';

export const options = {
  vus: Number(__ENV.VUS || 3),
  duration: __ENV.DURATION || '3m',
  thresholds: {
    http_req_failed: ['rate<0.03'],
    http_req_duration: ['p(95)<5000'],
    checks: ['rate>0.90'],
  },
};

function login() {
  const response = http.post(`${BASE_URL}/auth/token`, JSON.stringify({ username: USERNAME, password: PASSWORD }), {
    headers: { 'Content-Type': 'application/json' },
  });
  check(response, {
    'auth/token status < 500': (r) => r.status < 500,
    'auth/token returned token or auth disabled compatible': (r) => r.status === 200 && Boolean(r.json('token')),
  });
  return response.status === 200 ? response.json('token') : (__ENV.API_TOKEN || 'sentinela-demo-token');
}

function authHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
}

function get(path, token, name) {
  const response = http.get(`${BASE_URL}${path}`, { headers: authHeaders(token) });
  check(response, {
    [`${name} status < 500`]: (r) => r.status < 500,
    [`${name} latency < 5s`]: (r) => r.timings.duration < 5000,
  });
  return response;
}

export default function () {
  const token = login();

  group('core api', () => {
    get('/metrics', token, 'metrics');
    get('/search?q=BRUTE_FORCE', token, 'search');
    get('/alerts?range=24h', token, 'alerts');
    get('/incidents?limit=100&offset=0', token, 'incidents');
  });

  group('demo ingestion', () => {
    const response = http.post(`${BASE_URL}/demo/simulate-attack`, null, { headers: authHeaders(token) });
    check(response, {
      'demo simulate status < 500': (r) => r.status < 500,
      'demo simulate accepted for admin/analyst': (r) => [200, 201, 403].includes(r.status),
    });
  });

  group('websocket', () => {
    const response = ws.connect(`${WS_URL}?token=${encodeURIComponent(token)}`, {}, (socket) => {
      socket.setTimeout(() => socket.close(), 1500);
    });
    check(response, {
      'websocket connected or rejected cleanly': (r) => [101, 401, 403].includes(r && r.status),
    });
  });

  sleep(SLEEP_SECONDS);
}
