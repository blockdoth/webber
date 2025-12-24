// blog.typ — Example Typst blog post



#set text(
  size: 11pt,
)

#set heading(numbering: "1.")

#align(center)[
  = Building My First Typst Blog
  *A minimal example blog post*

  _Jane Doe · 2025-03-14_
]

---

== Introduction

Typst is a modern typesetting system designed to be *fast*, *expressive*, and
*pleasant to write*. In this post, I’ll show how a simple blog article can be
written entirely in Typst.

If you already know Markdown or LaTeX, Typst will feel familiar—but cleaner.

== Why Typst?

Here are a few reasons I like Typst:

- Simple, readable syntax
- Built-in scripting and layout logic
- No fragile compilation steps
- Excellent PDF output

> “Typst feels like LaTeX redesigned for humans.”

== Images

You can easily include images:
#figure(
  image("../images/image.png", width: 70%),
  caption: [A sample image used in the blog post.]
)

== Code Blocks

Typst supports fenced code blocks with syntax highlighting:

```rust
fn main() {
    println!("Hello, Typst!");
}```
#grid(
  columns: 2,
  [Typst supports fenced code blocks with syntax highlighting:
],[Typst supports fenced code blocks with syntax highlighting:
]
)

$ A = pi r^2 $
$ "area" = pi dot "radius"^2 $
$ cal(A) :=
    { x in RR | x "is natural" } $
#let x = 5
$ #x < 17 $
