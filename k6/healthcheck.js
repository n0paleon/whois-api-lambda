import http from 'k6/http';
import { sleep, check } from 'k6';

export const options = {
  vus: 15,
  duration: '30s',
};

export default function() {
  let res = http.get('https://whois.turuapi.my.id/v1/health-check');
  check(res, { "status is 200": (res) => res.status === 200 });
}
