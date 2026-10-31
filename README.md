# elf-ster.github.io
DDLD navidad

## Draw the pairs

Install [uv](https://docs.astral.sh/uv/), then create `messages.json` next to `encrypt.py`. It maps each person's passphrase to their name, and is never committed:

```json
{
  "first secret passphrase": "Name",
  "second secret passphrase": "Another name"
}
```

Then run:

```sh
uv run encrypt.py
```

uv installs Python and the dependencies the first time. The script draws the pairs at random and encrypts them into `index.html`, which you then commit and push to publish.

Every run draws new pairs, so don't run it again once people have looked up their recipient.
