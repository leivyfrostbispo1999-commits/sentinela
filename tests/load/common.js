import http from 'k6/http';
import { check, sleep } from 'k6';

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';
export const API_TOKEN = __ENV.API_TOKEN || 'sentinela-demo-token';
export const SLEEP_SECONDS = Number(__ENV.SLEEP_SECONDS || 1);

export const headers = {
  Authorization: `Bearer ${API_TOKEN}`,
  'Content-Type': 'application/json',
};

export function assertOk(response, name) {
  check(response, {
    [`${name} status < 500`]: (r) => r.status < 500,
    [`${name} latency p95 candidate`]: (r) => r.timings.duration < 1500,
  });
}

export function hit(path, name) {
  const response = http.get(`${BASE_URL}${path}`, { headers });
  assertOk(response, name);
  sleep(SLEEP_SECONDS);
  return response;
}
