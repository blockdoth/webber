last benchmark:
```shell
wrk -t4 -c100 -d10s http://127.0.0.1:4000/home
Running 10s test @ http://127.0.0.1:4000/home
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     2.44ms  454.15us   6.79ms   87.03%
    Req/Sec     9.94k     0.94k   11.08k    77.75%
  395606 requests in 10.02s, 0.92GB read
Requests/sec:  39496.60
Transfer/sec:     94.20MB
```

After styling

```shell
wrk -t4 -c100 -d10s http://127.0.0.1:4000/home

Running 10s test @ http://127.0.0.1:4000/home
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     3.24ms  574.22us   6.96ms   79.49%
    Req/Sec     7.56k   674.39     8.61k    61.75%
  300969 requests in 10.01s, 1.42GB read
Requests/sec:  30077.04
Transfer/sec:    145.31MB
```