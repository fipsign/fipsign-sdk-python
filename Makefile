# FIPSign Python SDK — Build & publish helpers

.PHONY: publish test clean

# Publish to PyPI — cleans dist/ first to avoid uploading old versions
publish:
	rm -rf dist/
	python -m build
	twine upload dist/*

# Run integration tests
test:
	FIPSIGN_API_KEY=$$FIPSIGN_API_KEY \
	WEBHOOK_URL=$$WEBHOOK_URL \
	WEBHOOK_SITE_TOKEN=$$WEBHOOK_SITE_TOKEN \
	python tests/test_sdk.py

# Remove build artifacts
clean:
	rm -rf dist/ build/ fipsign_sdk.egg-info/
