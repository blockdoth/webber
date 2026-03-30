WRONG but kept for reference 

```
.
├── content
│   └── posts
│       ├── post_1.md
│       ├── post_2.md
│       └── post_3.md
├── static
│   ├── fonts
│   └── images
│       └── image.png
└── templates
    ├── components
    │   └── post-thumbnail.html
    ├── layout
    │   ├── footer.html
    │   ├── hotreload.html
    │   ├── nav.html
    │   └── structure.html
    └── pages
        ├── home.html
        ├── post.html
        └── posts-overview.html
```

I have 3 folder types, static speaks for itself and will be the only folder directly served, content will contain markdown that gets rendered into html to be referenced internally and then there is templates.

`templates/pages` will contain the actual pages to be served, all the rest is internal.

for templating I plan to use direct paths as references to load snippets, marked by a starting `@` and direct variables to be found by `&` (dont want to be associated with php)

```html
<!DOCTYPE html>
<head>
  {{@templates/layout/hotreload.html if &hot-reload}}
</head>
<body>
    {{@templates/layout/nav.html}}
    {{&body}}
    {{@templates/layout/footer.html}}
</body>
```
these references will be recursively resolved and replaced with html during compilation / hotreload. For that distinction I need a simple conditional.

```html
<h1>All posts</h1>

{{/components/post-thumbnail for /content/posts}}

```
As I said all files in content will be converted to html, because I store them in a prefix tree I can querry them at once using the partial path and apply the `post-thumbnail` template



insp:
https://www.omarpolo.com/post/template.html
https://leapcell.medium.com/implementing-template-engine-from-scratch-like-jinja2-or-django-templates-ad3a37279eef