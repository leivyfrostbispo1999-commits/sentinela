import { BASE_URL, headers, hit, assertOk } from './common.js';
import http from 'k6/http';

export const options = {
  vus: Number(__ENV.VUS || 3),
  duration: __ENV.DURATION || '3m',
  thresholds: {
    http_req_failed: ['rate<0.03'],
    http_req_duration: ['p(95)<5000'],
  },
};

export default function () {
  const incidents = hit('/incidents?limit=100&offset=0', 'incidents');
  hit('/alerts?range=24h', 'alerts');
  const payload = incidents.json();
  const incidentId = payload && payload.data && payload.data[0] && payload.data[0].incident_id;
  if (incidentId) {
    assertOk(http.get(`${BASE_URL}/reports/incident/${encodeURIComponent(incidentId)}.md`, { headers }), 'reports markdown');
  } else {
    hit('/metrics/summary', 'metrics summary fallback');
  }
}
