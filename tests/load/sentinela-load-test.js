import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Metricas customizadas
export const errorRate = new Rate('http_errors');
export const apiLatency = new Trend('api_latency');

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:5000';

export const options = {
  stages: [
    { duration: '10s', target: 50 },  // Ramp-up: 50 VUs em 10s
    { duration: '30s', target: 50 },  // Plateau: mantem 50 VUs por 30s
    { duration: '10s', target: 200 }, // Spike: sobe para 200 VUs em 10s (Testando backpressure/degradacao)
    { duration: '20s', target: 200 }, // Sustenta o Spike
    { duration: '10s', target: 0 },   // Ramp-down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'], // Latencia p95 < 500ms, p99 < 1s
    'http_errors': ['rate<0.05'], // Taxa de erro menor que 5%
  },
};

export default function () {
  // 1. Teste de Throughput na listagem de alertas (Simulando Dashboard)
  const resAlerts = http.get(`${BASE_URL}/alertas?limit=50`);
  
  const successAlerts = check(resAlerts, {
    'status is 200 (alerts)': (r) => r.status === 200,
    'response time OK': (r) => r.timings.duration < 1000,
  });
  
  if (!successAlerts) {
    errorRate.add(1);
  }
  apiLatency.add(resAlerts.timings.duration);

  sleep(0.5);

  // 2. Teste de Busca (Pesado para o banco de dados / OpenSearch)
  const resSearch = http.get(`${BASE_URL}/search?q=failed_login`);
  
  const successSearch = check(resSearch, {
    'status is 200 or 404 (search)': (r) => r.status === 200 || r.status === 404,
  });

  if (!successSearch) {
    errorRate.add(1);
  }
  apiLatency.add(resSearch.timings.duration);

  sleep(1);
}
