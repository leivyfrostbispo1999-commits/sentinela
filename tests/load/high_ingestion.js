import { sleep } from 'k6';
import { BASE_URL, headers, assertOk } from './common.js';
import http from 'k6/http';

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '2m',
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<1200'],
  },
};

export default function () {
  const response = http.post(`${BASE_URL}/demo/simulate-attack`, null, { headers });
  assertOk(response, 'simulate attack ingestion');
  sleep(0.5);
}

