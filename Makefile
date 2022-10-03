.PHONY: all dependencies dist pypi-test pypi description check test coverage coverage-report clean-dist clean

all: dependencies dist check test clean

dependencies:
	@echo "Installing dependencies:"
	python3 -m pip install --upgrade pip setuptools wheel
	pip3 install flake8 pytest
	pip3 install -r requirements.txt

dist: clean-dist
	pip3 install wheel
	python3 setup.py sdist bdist_wheel

pypi-test: dist
	# NOTE: twine will read TWINE_USERNAME and TWINE_PASSWORD from environment
	pip3 install twine
	twine check dist/*
	@echo "Uploading to PyPI (test instance):"
	twine upload --repository testpypi dist/*

pypi: dist
	# NOTE: twine will read TWINE_USERNAME and TWINE_PASSWORD from environment
	pip3 install twine
	twine check dist/*
	@echo "Uploading to PyPI:"
	twine upload dist/*

description: dependencies
	python3 -m openvas_edxml.cli -q --dump-description > transcoder.rst

check:
	@echo "Checking your code..."
	@python3 -m flake8 --max-line-length=120 openvas_edxml/ test/ && echo "Well done. Your code is in shiny style!"

test: dependencies
	@echo "Running tests:"
	@python3 -m pytest test/ -W ignore::DeprecationWarning
	# Below fails when regenerating the rst document that describes
	# the transcoder results in changes in the Git repo. That happens when
	# the rst document is not up to date.
	$(MAKE) description && git diff --exit-code '*.rst'

coverage: dependencies
	@echo "Gathering coverage data:"
	@python3 -m coverage run --omit '*/venv/*' -m pytest test/ -W ignore::DeprecationWarning

coverage-report:
	coverage html

clean-dist:
	rm -rf build dist openvas_edxml.egg-info

clean: clean-dist
	find . -name '*.py[co]' -delete
	rm -rf .coverage htmlcov
