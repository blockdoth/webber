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

I am specifically trying to solve parsing nested block quotes like this

```
> normal
>> nested
>> nested
> normal
```
which I tokenize into
```
[Quote(1), Text("normal"), Quote(2), Text("nested"), Quote(2), Text("nested"), Quote(1), Text("normal")]
```
(the actual tokens contain spans not sizes btw)
which needs to be parsed into
```
BlockQuote {
  content: ["normal", BlockQuote {content: ["nested", "nested:]}, "normal"]
}
```

prior to this I completely separated out block parsing and block content parsing, because I did not support nested blocks. (block quotes, lists). To add nesting I need to collect each line belonging to the same quote and then recursively parse those as a block. However to be aware of recursive depth I would either have to modify my parse function signature, or decrement the `Quote(depth)` tokens. The former I dont like, but the later makes it so I cant just pass a slice of the original  tokenstream to the recursive call because I need to modify it. So i need to collect it into a temporary vec. My parse function takes a slice so need to reference that vec as a slice. This was were rust started to complain because that temprory vec's lifetime does not survive the parse function, which is relevant, because it the parsed blocks dont own their content. To convince the compiler I need to let it know that while the input stream lives longer than the function, token may get dropped 

https://blog.dend.ro/self-modifying-rust/