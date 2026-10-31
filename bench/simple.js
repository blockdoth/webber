import http from 'k6/http';

export const options = {
    scenarios: {
        baseline: {
            executor: 'constant-vus',
            vus: 100,
            duration: '30s',
        },
    },
};

export default function () {
    http.get('http://127.0.0.1:4000/home');
}