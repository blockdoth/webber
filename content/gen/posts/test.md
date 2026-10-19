::::
title = "test"
published = 2026-07-05
::::



# Test

---
~test~
*bold*


`test 1` _test 2_ ~test~ *test 4* 
~test~
- 1
- 2



1. 2
1. 2
1. 2
1. 2

> test
>
[_link text_](http://dev.nodeca.com)


![image](/images/image.png)

```css

  .post_entry {
    border: 1px solid white;
    color: white;
    padding: 10px;
    margin: 20px;
    display: flex;     
    gap: 2;           
  }  

```

```rust
#[derive(Debug)]
struct TrieNode<T> {
    asset: Option<T>,
    children: HashMap<String, TrieNode<T>>,
}

```

```javascript
const ws = new WebSocket("ws://127.0.0.1:4000/ws");
ws.onopen = () => console.log("Websocket connected!");
ws.onmessage = (event) => {
  if ( event.data == "reload" ) {
    window.location.reload();
  };
}

```