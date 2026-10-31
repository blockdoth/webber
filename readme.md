

Rust code hotreloading notes:

Start with a shared codebase, fork as soon as possible CoW should make it cheap even though the binary is quite large because of the assets.

The forked process should share a unix socket with the main process, over which it sends all incoming data from `/api`
Upon change in a specific dir (outside of src?) the fork has to be recompiled

This can either be done by the fork itself (can it?) or by having the main process, recompile, kill and relaunch the fork

Problems:
- What to do with the database... 
  - Shared readers is possible with SQlite, shared writers is not
  - Database writes could be send back to the main process, but that adds latency
- How to handle the recompilation
- How to pass 

Requirements
- In release mode the API code must be integrated into a single process, only in debug mode can it run seperatly


Learned something:
- The socket read and write buffer size is an important upper bound for request 
- DB syncs can blow up the waiting buffer, causing a cascading failure