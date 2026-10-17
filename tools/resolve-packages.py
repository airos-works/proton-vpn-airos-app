#!/usr/bin/env python3
"""Resolve HaikuPorts packages for the test VM, offline from a repo index.

  resolve-packages.py REPO_VERBOSE INSTALLED_LIST WANTED...

REPO_VERBOSE is the output of `package_repo list -v <repo>`; INSTALLED_LIST
holds the file names of the packages already on the disk image, one per line.
Prints one "name-version-arch.hpkg" per line for every package that has to be
added so that WANTED and their requirements are satisfied.
"""
import re
import sys


def parse_repo(path):
	packages = {}
	current = None
	for line in open(path, encoding='utf-8', errors='replace'):
		line = line.rstrip('\n')
		if line == 'package-attributes:':
			current = {'provides': [], 'requires': []}
			continue
		if current is None or not line.startswith('\t'):
			continue
		key, _, value = line.strip().partition(': ')
		if key == 'name':
			current['name'] = value
			packages[value] = current
		elif key in ('version', 'architecture'):
			current[key] = value
		elif key == 'provides':
			current['provides'].append(value.split(' ')[0])
		elif key == 'requires':
			current['requires'].append(re.split(r'[<>=! ]', value, 1)[0])
	return packages


def installed_names(path):
	names = set()
	for line in open(path):
		line = line.strip()
		if not line.endswith('.hpkg'):
			continue
		# name-version-revision-arch.hpkg; names never contain '-'
		names.add(line.split('-')[0])
	return names


def main():
	repo = parse_repo(sys.argv[1])
	installed = installed_names(sys.argv[2])
	provider = {}
	for name, info in repo.items():
		for item in info['provides'] + [name]:
			provider.setdefault(item, name)
	# Everything the installed packages provide counts as present.
	present = set(installed)
	for name in installed:
		if name in repo:
			present.update(repo[name]['provides'])
	# The system package provides many libraries and commands itself.
	present.update(['haiku', 'haiku_devel'])
	chosen = []
	todo = list(sys.argv[3:])
	while todo:
		item = todo.pop()
		if item in present:
			continue
		name = provider.get(item)
		if name is None:
			print('unresolved: ' + item, file=sys.stderr)
			continue
		if name in present:
			present.add(item)
			continue
		info = repo[name]
		chosen.append(info)
		present.add(name)
		present.update(info['provides'])
		todo.extend(info['requires'])
	for info in chosen:
		print('%s-%s-%s.hpkg' % (info['name'], info['version'], info['architecture']))


main()
