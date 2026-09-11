.PHONY: test lint build check clean

test:
	python -m pytest -q
	python ersec.py --self-test

build:
	rm -rf build dist *.egg-info
	python -m build

check: build
	python -m twine check dist/*

clean:
	rm -rf build dist *.egg-info .pytest_cache __pycache__ tests/__pycache__
