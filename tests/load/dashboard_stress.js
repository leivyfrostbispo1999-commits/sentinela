import { hit } from './common.js';

export const options = {
  vus: Number(__ENV.VUS || 3),
  duration: __ENV.DURATION || '3m',
  thresholds: {
    http_req_failed: ['rate<0.03'],
    http_req_duration: ['p(95)<3000'],
  },
};

export default function () {
  hit('/alerts?range=24h', 'alerts');
  hit('/metrics/summary', 'metrics summary');
  hit('/timeline?range=24h', 'timeline');
  hit('/campaigns', 'campaigns');
}
