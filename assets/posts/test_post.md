::::
published = 2103-04-04
summary = "sloppy test post"
::::

# Smooth sloperator
<!-- ![image](/images/image.png) -->

There is a particular kind of software that has become increasingly common.

It compiles.

It runs.

It has tests.

It has a README.

It may even have a beautifully designed landing page.

And yet, somewhere underneath all of it, there is an unmistakable feeling that something went wrong.

The code is **slop**.

Not necessarily broken code.

Not necessarily bad code.

Just code that exists because generating it was easier than thinking about whether it should exist in the first place.


# What is slop?
![image](/images/image.png)


Slop is software produced with insufficient consideration for its actual purpose.

It tends to have:

* too much abstraction;
* too many dependencies;
* too many comments explaining obvious things;
* too many layers;
* too many generated files;
* too many configuration options;
* too many features;
* too little understanding of the problem.

A classic example is:

```text
Need to read a file
       |
       v
File abstraction
       |
       v
Storage interface
       |
       v
Repository
       |
       v
Service
       |
       v
Controller
       |
       v
Dependency injection
       |
       v
read_to_string()
```

The actual operation was:

```rust
let contents = std::fs::read_to_string(path)?;
```

The rest is ceremony.



# Slop is not the same as bad code

This distinction matters.

Some very ugly code is excellent.

Some beautifully structured code is terrible.

A 20-line function with strange names can still solve the problem correctly.

A 2,000-line architecture can still be completely unnecessary.

Slop is therefore less about aesthetics and more about **the ratio between complexity and value**.

One way of thinking about it is:

```text
                 complexity
slop = ─────────────────────────
                  value
```

The higher that ratio becomes, the more slop you have.



# The 500-line function that should be 5 lines

Consider a function whose entire purpose is to determine whether a file exists.

Slop might look like:

```rust
pub trait FileExistenceChecker {
    fn exists(&self, path: &Path) -> bool;
}

pub struct DefaultFileExistenceChecker {
    filesystem: Arc<dyn FileSystem>,
}

impl FileExistenceChecker for DefaultFileExistenceChecker {
    fn exists(&self, path: &Path) -> bool {
        self.filesystem.metadata(path).is_ok()
    }
}

pub trait FileSystem {
    fn metadata(&self, path: &Path) -> io::Result<Metadata>;
}
```

The application now has:

* a trait;
* an implementation;
* another trait;
* an `Arc`;
* dynamic dispatch;
* dependency injection;
* a filesystem abstraction.

The original problem was:

```rust
std::fs::exists(path)
```

If the application genuinely needs interchangeable filesystems, the abstraction may be justified.

If it doesn't, this is architectural theater.



# The factory factory

Another common form of slop is an abstraction whose only purpose is to construct another abstraction.

For example:

```rust
pub trait UserRepository {
    fn find(&self, id: u64) -> Option<User>;
}

pub struct PostgresUserRepository {
    db: Database,
}

pub struct UserRepositoryFactory {
    db: Database,
}

impl UserRepositoryFactory {
    pub fn create(&self) -> Box<dyn UserRepository> {
        Box::new(PostgresUserRepository {
            db: self.db.clone(),
        })
    }
}
```

Then somewhere else:

```rust
let repository = UserRepositoryFactory::new(db).create();
```

The factory contains no meaningful decision.

It just does:

```rust
Box::new(PostgresUserRepository { ... })
```

So the architecture becomes:

```text
Factory
   ↓
Interface
   ↓
Implementation
   ↓
Database
```

when the actual requirement is:

```text
Database
   ↓
Repository
```

Factories are useful when construction actually contains meaningful policy.

A factory that only exists because "factories are good architecture" is slop.



# Dependency injection for a constant

This can get even more absurd.

Imagine:

```rust
pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}
```

and then:

```rust
pub struct Application {
    clock: Box<dyn Clock>,
}
```

If you need deterministic tests, this can be completely reasonable.

But sometimes this becomes:

```rust
pub trait Pi {
    fn value(&self) -> f64;
}

pub struct DefaultPi;

impl Pi for DefaultPi {
    fn value(&self) -> f64 {
        std::f64::consts::PI
    }
}
```

Eventually:

```rust
let pi = application
    .configuration()
    .mathematics()
    .constants()
    .pi()
    .value();
```

At some point the abstraction is no longer helping.

It is hiding the thing you actually wanted.

```rust
std::f64::consts::PI
```



# Slop loves configuration

Configuration is useful.

Infinite configuration is not.

Suppose a program needs a port:

```rust
struct Config {
    port: u16,
}
```

Simple.

Slop might turn this into:

```rust
struct ServerConfig {
    network: NetworkConfig,
}

struct NetworkConfig {
    listener: ListenerConfig,
}

struct ListenerConfig {
    address: AddressConfig,
}

struct AddressConfig {
    host: String,
    port: PortConfig,
}

struct PortConfig {
    value: u16,
    source: PortSource,
    validation: PortValidation,
}
```

And eventually:

```rust
config
    .server()
    .network()
    .listener()
    .address()
    .port()
    .value()
```

The application still needs:

```rust
u16
```

Configuration should represent actual decisions.

It should not turn every primitive into a framework.



# The wrapper problem

A common pattern in slop-heavy code is wrapping a type without adding behavior.

For example:

```rust
pub struct UserId(u64);

impl UserId {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}
```

This can be good.

A domain-specific `UserId` can prevent accidentally passing an `OrderId` where a `UserId` is expected.

But compare it with:

```rust
pub struct UserId {
    value: UserIdValue,
}

pub struct UserIdValue {
    raw: u64,
}

impl UserIdValue {
    pub fn raw(&self) -> u64 {
        self.raw
    }
}
```

Now we have:

```text
UserId
  ↓
UserIdValue
  ↓
u64
```

without gaining another meaningful invariant.

The question isn't:

> "Can I create another type?"

The question is:

> "What mistake does this type prevent?"



# Slop can hide simple algorithms

Consider a cache.

A simple implementation might be:

```rust
use std::collections::HashMap;

struct Cache {
    values: HashMap<String, String>,
}

impl Cache {
    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    fn insert(&mut self, key: String, value: String) {
        self.values.insert(key, value);
    }
}
```

That's a cache if the application only needs a lookup table.

But slop might produce:

```rust
trait CacheBackend {
    fn get(&self, key: &CacheKey) -> Option<CacheValue>;
    fn set(&mut self, key: CacheKey, value: CacheValue);
}

trait CachePolicy {
    fn should_evict(&self, entry: &CacheEntry) -> bool;
}

trait CacheSerializer {
    fn serialize(&self, value: &CacheValue) -> Vec<u8>;
}

struct CacheManager<B, P, S> {
    backend: B,
    policy: P,
    serializer: S,
}
```

Now you have 4 interfaces and several generic parameters.

And the program still needs:

```rust
HashMap
```

If you actually need TTLs, persistence, serialization, eviction policies, and multiple backends, those abstractions can be justified.

Otherwise, you've built a cache framework instead of a cache.



# Comments can become slop too

Consider:

```rust
// Check if the user exists.
if users.contains_key(&id) {
    // Return true if the user exists.
    return true;
}

// Return false if the user does not exist.
false
```

The comments provide no additional information.

The code already says exactly what it does.

The better version is:

```rust
users.contains_key(&id)
```

A useful comment explains something the code cannot.

For example:

```rust
// Keep this lookup separate from authentication because deleted users
// must still be recognized when processing historical events.
let user = users.get(&id);
```

The code explains **what**.

The comment explains **why**.



# Generated boilerplate can be slop

AI is particularly good at generating boilerplate.

Suppose you ask for a small error type.

You might get:

```rust
#[derive(Debug)]
pub enum UserError {
    UserNotFound,
    InvalidUserId,
    InvalidUsername,
    InvalidEmail,
    DatabaseError,
    SerializationError,
    ValidationError,
    InternalError,
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound => write!(f, "user not found"),
            Self::InvalidUserId => write!(f, "invalid user id"),
            Self::InvalidUsername => write!(f, "invalid username"),
            Self::InvalidEmail => write!(f, "invalid email"),
            Self::DatabaseError => write!(f, "database error"),
            Self::SerializationError => write!(f, "serialization error"),
            Self::ValidationError => write!(f, "validation error"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}
```

This isn't necessarily slop.

But if the application immediately converts all of these into:

```text
500 Internal Server Error
```

then most of the distinction may be meaningless.

Sometimes the correct error type is simply:

```rust
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
```

Or perhaps one meaningful domain error.

The right amount of structure depends on what the caller actually needs.



# AI makes slop cheap

This is where things become particularly interesting.

Before generative AI, producing a thousand lines of mediocre code required a human to type a thousand lines of mediocre code.

That imposed a natural constraint.

Now:

```text
"Build me a production-ready abstraction for X."
```

can produce:

```text
interface
implementation
factory
builder
configuration
error hierarchy
tests
documentation
examples
helper utilities
```

in seconds.

The cost of producing code has collapsed.

The cost of **understanding** that code has not.

That difference is extremely important.



# The economics of slop

Suppose writing code costs:

```text
                    10 minutes
```

and understanding it costs:

```text
                    2 hours
```

Humans naturally avoided unnecessary code because writing it was expensive.

AI changes this:

```text
Writing:

Human:  ████████████████████
AI:     █

Understanding:

Human:  ████████████████████
AI:     ████████████████████
```

The bottleneck moves.

The scarce resource is no longer typing.

It is **attention**.



# More code is not more progress

There is a dangerous psychological effect here.

A generated diff containing:

```diff
+ 1,842 lines
-    13 lines
```

looks like progress.

It feels substantial.

There are new abstractions.

There are tests.

There are comments.

There are types.

There are files.

Something must have happened.

But the actual value might be:

```text
+ 1 feature
+ 0 reliability
+ 0 performance
- maintainability
```

The size of a diff is not a measure of progress.

Sometimes the best change is:

```diff
- 184 lines
+   7 lines
```



# The "just in case" abstraction

One of the most common causes of slop is preparing for requirements that don't exist.

For example:

```rust
trait ImageDecoder {
    fn decode(&self, data: &[u8]) -> Image;
}
```

Then:

```rust
struct JpegDecoder;
struct PngDecoder;
struct GifDecoder;
struct WebpDecoder;
struct AvifDecoder;
```

But the application only supports JPEG.

Someone may say:

> "We should abstract this now because we'll probably support PNG later."

Maybe.

Or maybe the application will never support PNG.

You have now paid for:

```text
design
implementation
testing
documentation
maintenance
```

for a hypothetical future.

A simpler implementation is:

```rust
fn decode_jpeg(data: &[u8]) -> Image {
    // ...
}
```

When PNG actually becomes necessary, **then** introduce the abstraction.

This is one of the most useful forms of engineering discipline:

> Don't pay today's complexity cost for tomorrow's hypothetical requirement.



# Premature generalization

Consider an API that currently needs one input type:

```rust
fn process_image(image: &Jpeg) -> Result<Image, Error>
```

An AI-generated redesign might immediately turn it into:

```rust
trait ImageSource {
    type Pixel;
    type Metadata;
    type Error;

    fn dimensions(&self) -> Dimensions;
    fn pixels(&self) -> impl Iterator<Item = Self::Pixel>;
    fn metadata(&self) -> Self::Metadata;
}
```

This is intellectually impressive.

It is also completely unnecessary if the program processes JPEG files.

The generalized API may actually make the code harder to understand.

A good abstraction usually emerges from **multiple concrete cases**.

If there is only one case, you often don't know what the abstraction should be yet.



# The abstraction should follow the problem

Suppose you initially have:

```rust
fn render_jpeg(data: &[u8]) -> Vec<u8>
```

Then later you add PNG:

```rust
fn render_png(data: &[u8]) -> Vec<u8>
```

Now you have evidence that both operations share a concept.

At this point an abstraction might make sense:

```rust
trait ImageDecoder {
    fn decode(&self, data: &[u8]) -> Result<Image, Error>;
}
```

The important difference is the direction:

```text
Bad:

abstraction
    ↓
invent concrete implementations
```

versus:

```text
Better:

concrete implementations
    ↓
observe repetition
    ↓
extract abstraction
```

This is sometimes called **evolutionary design**.



# Slop hides performance problems

Slop isn't only a readability problem.

Abstractions can make performance characteristics difficult to see.

For example:

```rust
fn process(items: &[Item]) {
    items
        .iter()
        .map(|item| item.clone())
        .filter(|item| expensive_check(item))
        .collect::<Vec<_>>();
}
```

The code looks clean.

But it might be doing:

```text
clone
clone
clone
clone
allocate Vec
allocate elements
run expensive check
```

A simpler implementation can make the cost obvious:

```rust
fn process(items: &[Item]) {
    for item in items {
        if expensive_check(item) {
            // Process item directly.
        }
    }
}
```

The second version isn't automatically better.

The important part is that the performance characteristics are visible.

Abstraction should not make expensive operations invisible.



# The iterator version can be slop too

Rust makes it possible to write extremely expressive chains:

```rust
let result = items
    .iter()
    .filter(|x| x.enabled)
    .map(|x| x.value.clone())
    .filter(|x| !x.is_empty())
    .map(|x| x.trim().to_owned())
    .collect::<Vec<_>>();
```

This is perfectly valid Rust.

But sometimes:

```rust
let mut result = Vec::new();

for item in items {
    if !item.enabled {
        continue;
    }

    if item.value.is_empty() {
        continue;
    }

    result.push(item.value.trim().to_owned());
}
```

is easier to understand.

"More idiomatic" is not automatically the same thing as "better."

Code is communication.



# Slop can be optimized away

The good news is that slop is often surprisingly easy to remove.

Start with:

```rust
let user = user_repository
    .get_user_service()
    .get_user_manager()
    .find_user_by_id(id)?;
```

Ask what each layer actually contributes.

Perhaps:

```rust
fn find_user(&self, id: UserId) -> Result<User, Error> {
    self.db.query_user(id)
}
```

Then:

```rust
let user = db.query_user(id)?;
```

Then perhaps the entire helper disappears.

This process can be repeated:

```text
remove wrapper
     ↓
remove wrapper
     ↓
remove trait
     ↓
remove factory
     ↓
remove dependency
     ↓
remove file
```

The application still works.

It just has less software.



# The deletion test

One of the best questions to ask when reviewing code is:

> **What happens if I delete this?**

For a function:

```rust
fn normalize_user_name(name: &str) -> String {
    name.trim().to_lowercase()
}
```

Maybe it is useful.

For:

```rust
fn normalize_user_name_with_context(
    context: &NormalizationContext,
    options: &NormalizationOptions,
    strategy: &dyn NormalizationStrategy,
    name: &str,
) -> NormalizedUserName {
    // ...
}
```

the question becomes much more important.

What problem does all this machinery solve?

If the answer is:

```rust
name.trim().to_lowercase()
```

the machinery is probably the problem.



# AI should increase the amount of thinking

The natural temptation is to use AI like this:

```text
idea
  ↓
prompt
  ↓
code
  ↓
merge
```

A better workflow is:

```text
             ┌─────────────┐
             │   problem   │
             └──────┬──────┘
                    ▼
             understand it
                    │
                    ▼
              design simply
                    │
                    ▼
               ask AI
                    │
                    ▼
               inspect it
                    │
                    ▼
               simplify it
                    │
                    ▼
                measure
                    │
                    ▼
                 ship
```

The AI can accelerate implementation.

It should not replace engineering judgment.



# The AI review question

After generating code, don't only ask:

> "Does this work?"

Also ask:

> "Why is this code this large?"

For example, if AI produces:

```rust
pub struct Service {
    repository: Arc<dyn Repository>,
    cache: Arc<dyn Cache>,
    metrics: Arc<dyn Metrics>,
    logger: Arc<dyn Logger>,
    config: Arc<Config>,
}
```

don't immediately accept it.

Ask:

```text
Do I need a repository abstraction?
Do I need a cache?
Do I need metrics?
Do I need a logger?
Do these need dynamic dispatch?
Do these need Arc?
Does this configuration need to be shared?
```

You may discover that the actual application is:

```rust
pub struct Service {
    db: Database,
}
```

That's not less sophisticated.

It is simply more honest about the problem.



# AI-generated tests can be slop too

Tests are valuable, but generated tests can easily test implementation details instead of behavior.

For example:

```rust
#[test]
fn test_get_user_calls_repository_once() {
    // Mock repository...
}
```

This locks the implementation to a particular internal design.

A better test might be:

```rust
#[test]
fn returns_user_when_user_exists() {
    let user = find_user(42).unwrap();

    assert_eq!(user.id, 42);
}
```

The first test says:

> "The implementation must work this way."

The second says:

> "The program must behave this way."

Good tests protect behavior.

Sloppy tests protect architecture.



# Generated documentation can be slop

AI can also generate enormous documentation for trivial code.

For example:

```rust
/// Adds two integers together.
///
/// This function takes two integer values as parameters.
/// It then computes their mathematical sum.
/// The resulting value is returned to the caller.
///
/// # Arguments
///
/// * `a` - The first integer.
/// * `b` - The second integer.
///
/// # Returns
///
/// The sum of `a` and `b`.
fn add(a: i32, b: i32) -> i32 {
    a + b
}
```

This is technically correct.

It is also useless.

Compare:

```rust
fn add(a: i32, b: i32) -> i32 {
    a + b
}
```

Documentation should preserve knowledge that would otherwise be lost.

It shouldn't merely narrate the syntax.



# Slop has a compounding cost

The dangerous thing about slop is that it accumulates.

Today:

```text
one unnecessary abstraction
```

Tomorrow:

```text
another abstraction depends on it
```

Next month:

```text
five services depend on both
```

Eventually:

```text
nobody knows why it exists
```

And finally:

```text
"We can't remove it."
```

The code has become legacy.

The original five-line decision has now become an architectural constraint.



# The cost of code is not writing it

This is perhaps the most important point.

The initial cost of code is:

```text
time to write
```

But the lifetime cost is closer to:

```text
             writing
                +
             reading
                +
             debugging
                +
             testing
                +
             reviewing
                +
             documenting
                +
             maintaining
                +
             changing
                +
             explaining
```

AI dramatically reduces the first term.

It does not eliminate the others.

So if AI allows you to generate code ten times faster, that doesn't mean you should have ten times as much code.

It means you have an opportunity to spend more time deciding **what deserves to exist**.



# The best AI-generated code may be code you delete

There is an interesting paradox here.

AI can be extremely useful for producing a first implementation that you subsequently throw away.

The generated code can help answer:

* What does the API need to look like?
* Which edge cases exist?
* What assumptions did I miss?
* What would a straightforward implementation look like?

Then you can write the final version yourself.

The value was not necessarily the code.

The value was the **information extracted from generating it**.



# Slop is a systems problem

At some point, this stops being about individual programmers.

Organizations reward visible output.

A large pull request looks productive.

A new subsystem looks productive.

A new framework looks productive.

Deleting 4,000 lines because they were unnecessary looks suspiciously like doing nothing.

But software has a carrying cost.

Every line introduces some combination of:

```text
maintenance
testing
documentation
cognitive load
bugs
dependencies
build time
review time
migration cost
```

The true cost of software is therefore not its initial creation.

It is everything that happens **afterwards**.



# The goal isn't less code

This is important.

The goal is not:

> "Write as few lines as possible."

Golfing code is not engineering.

The goal is:

> **Write only as much code as the problem actually requires.**

Sometimes that means:

```rust
let value = map.get(key);
```

Sometimes it means:

```rust
let result = complicated_algorithm(
    input,
    configuration,
    index,
    cache,
    metadata,
);
```

The second isn't slop just because it's longer.

The question is whether the complexity is buying something.



# Good software has negative space

One of the easiest ways to recognize mature software is not by what it contains.

It is by what it **doesn't** contain.

There isn't necessarily:

* a framework for every subsystem;
* an abstraction for every function;
* a configuration option for every value;
* a dependency for every problem;
* a comment for every line;
* a test for every implementation detail.

There is simply enough machinery to solve the problem reliably.

The rest is left out.



# Conclusion

AI has made generating software almost trivial.

That is simultaneously one of the most powerful and dangerous changes in software development.

When code is expensive to produce, engineers naturally ask:

> "Do we really need this?"

When code is nearly free, that question becomes much easier to forget.

And that is where slop comes from.

The solution isn't to stop using AI.

It is to become better at saying:

```text
No.

We don't need this abstraction.

We don't need this dependency.

We don't need these 800 lines.

We don't need a factory for a factory.

We don't need an interface with one implementation.

We don't need configuration for a constant.

We can just do this.
```

Because the most valuable line of code is sometimes the one you never write.

And the second most valuable might be the one you delete.
