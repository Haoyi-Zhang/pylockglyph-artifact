.PHONY: replay study test paper clean

PDFLATEX ?= pdflatex
BIBTEX ?= bibtex

replay:
	./run_replay.sh

study:
	python3 tool/run_study.py

test:
	python3 tool/run_tests.py

paper:
	python3 tool/paper_data.py
	cd ../paper && $(PDFLATEX) -interaction=nonstopmode -halt-on-error main.tex
	cd ../paper && ( $(BIBTEX) main || /usr/bin/bibtex.original main )
	cd ../paper && $(PDFLATEX) -interaction=nonstopmode -halt-on-error main.tex
	cd ../paper && $(PDFLATEX) -interaction=nonstopmode -halt-on-error main.tex
	cd ../paper && $(PDFLATEX) -interaction=nonstopmode -halt-on-error supplement.tex
	cd ../paper && $(PDFLATEX) -interaction=nonstopmode -halt-on-error supplement.tex

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
	rm -f ../paper/*.aux ../paper/*.bbl ../paper/*.blg ../paper/*.log ../paper/*.out ../paper/*.fls ../paper/*.fdb_latexmk ../paper/*.synctex.gz
