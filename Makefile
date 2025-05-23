.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: site
site:
	uv run --only-group docs mkdocs build

.PHONY: site-live
site-live:
	uv run --only-group docs mkdocs serve

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

.PHONY: refresh-schemas
refresh-schemas:
	curl https://json.schemastore.org/github-workflow.json > crates/zizmor/src/data/github-workflow.json
	curl https://json.schemastore.org/github-action.json > crates/zizmor/src/data/github-action.json

.PHONY: webhooks-to-contexts
webhooks-to-contexts: support/known-safe-contexts.txt

support/known-safe-contexts.txt: support/webhooks-to-contexts.py
	$<

.PHONY: codeql-injection-sinks
codeql-injection-sinks: support/codeql-injection-sinks.json

support/codeql-injection-sinks.json: support/codeql-injection-sinks.py
	$< > $@

.PHONY: pinact
pinact:
	pinact run --update --verify
