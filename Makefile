.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: site
site:
	uv run --no-project --only-group docs mkdocs build

.PHONY: site-live
site-live:
	uv run --no-project --only-group docs mkdocs serve

.PHONY: snippets
snippets: trophies sponsors
	cargo run -- -h > docs/snippets/help.txt

.PHONY: trophies
trophies: docs/snippets/trophies.md

docs/snippets/trophies.md: docs/snippets/trophies.txt docs/snippets/render-trophies.py
	uv run --no-project docs/snippets/render-trophies.py > $@

.PHONY: sponsors
sponsors: docs/snippets/sponsors.html

docs/snippets/sponsors.html: docs/snippets/sponsors.json docs/snippets/render-sponsors.py
	uv run --no-project docs/snippets/render-sponsors.py > $@
