.PHONY: check format-check policy-check scaffold-check

check:
	python3 scripts/check_repo.py all

format-check:
	python3 scripts/check_repo.py format

policy-check:
	python3 scripts/check_repo.py policy

scaffold-check:
	python3 scripts/check_repo.py scaffold
