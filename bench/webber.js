
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';
import { parseHTML } from 'k6/html';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:4000';

export const options = {
    scenarios: {
        visitors: {
            executor: 'ramping-vus',
            startVUs: 10000,
            stages: [
                { duration: '30s', target: 40000 },
            ],
            gracefulRampDown: '10s',
            gracefulStop: '15s',
        },
    },

    thresholds: {
        http_req_failed: ['rate<0.01'],
        http_req_duration: ['p(95)<500'],
    },
};

const routes = [
    { path: '/home', weight: 35 },
    { path: '/posts', weight: 30 },
    { path: '/quotes', weight: 15 },
    { path: '/gallery', weight: 10 },
    { path: '/about', weight: 7 },
    { path: '/stats', weight: 3 },
];

function getPage(path) {
    const response = http.get(`${BASE_URL}${path}`, {
        tags: { page: path },
    });

    check(response, {
        [`${path} returns 200`]: (r) => r.status === 200,
    });

    return response;
}

function randomRoute() {
    const total = routes.reduce((sum, route) => sum + route.weight, 0);
    let choice = Math.random() * total;

    for (const route of routes) {
        choice -= route.weight;
        if (choice < 0) return route.path;
    }

    return '/home';
}

function browsePosts() {
    group('Browse posts', () => {
        const response = getPage('/posts');

        if (!response.body) return;

        // Discover individual post links from the posts listing.
        const doc = parseHTML(response.body);
        const links = doc.find('a').toArray()
            .map((a) => a.attr('href'))
            .filter((href) =>
                href &&
                href.startsWith('/posts/') &&
                !href.includes('#')
            );

        if (links.length > 0) {
            sleep(randomIntBetween(2, 6));

            const post = links[randomIntBetween(0, links.length - 1)];

            getPage(post);
        }
    });
}

function browseGallery() {
    group('Browse gallery', () => {
        getPage('/gallery');
    });
}

function browseSite() {
    group('Browse site', () => {
        getPage('/home');

        sleep(randomIntBetween(2, 5));

        const destination = randomRoute();

        if (destination === '/posts') {
            browsePosts();
        } else if (destination === '/gallery') {
            browseGallery();
        } else {
            getPage(destination);
        }
    });
}

export default function () {
    const action = Math.random();

    if (action < 0.50) {
        browseSite();
    } else if (action < 0.80) {
        browsePosts();
    } else if (action < 0.90) {
        browseGallery();
    } else {
        getPage(randomRoute());
    }

    // Time spent reading / interacting before the next navigation.
    sleep(randomIntBetween(2, 8));
}
