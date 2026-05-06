import { sleep } from 'k6';
import { BASE_URL, headers, assertOk, hit } from './common.js';
import http from 'k6/http';

export const options = {
  scenarios: {
    incident_burst: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 6),
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: Number(__ENV.VUS || 12),
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<1500'],
  },
};

export default function () {
  assertOk(http.post(`${BASE_URL}/demo/simulate-attack`, null, { headers }), 'create incident');
  hit('/incidents?limit=50&offset=0', 'list incidents');
  sleep(0.2);
}

