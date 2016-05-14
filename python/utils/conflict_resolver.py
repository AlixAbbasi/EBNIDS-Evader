#!/usr/bin/python

"""
Resolve conflicting encoders using dependency resolution

We say i depends on j if i can no longer function properly if it is encapsulated in j (eg. encoderj(encoderi(payload)) )
For example because it has to be executed as the first encoder of all or because j triggers heuristics i is meant to evade, etc.

So we find an order of the selected encoders where there are no 'dependencies'
"""

import itertools
import networkx as nx

class conflict_resolver:
	def __init__(self, dependency_specs):
		self.dependency_specs = dependency_specs
		return

	def order_chain(self, evasion_chain, ordering):
		return [evasion_chain[i] for i in ordering]

	# Check if a depends on b (ie. a cannot function properly when encoded by b)
	def depends(self, a, b):
		return (b[1] in self.dependency_specs[a[1]])

	# Perform dependency resolution
	def resolve(self, evasion_chain):
		encoders = []

		for i in xrange(len(evasion_chain)):
			encoders.append((i, evasion_chain[i][1]['evader']))

		# Permutations
		permutes = itertools.permutations(encoders, len(evasion_chain))

		for c in permutes:

			# Build graph g
			g = nx.DiGraph()

			for i in range(0, len(c)):
				g.add_node(i)
				for j in range(0, len(c)):
					# Check if i depends on j (ie. does i no longer function if it is encapsulated in j?)
					if(self.depends(c[i], c[j])):
						g.add_edge(i, j)

			# Check if we have a topological ordering to rule out cyclic dependencies
			# (cyclic dependencies will cause "ValueError: Cyclic dependencies exist among these items:")
			try:
				# TODO: optimize candidate selection? Now we just go for the first one
				t = nx.topological_sort(g)

				# for each set in the ordering (sets are topologically ordered, eg. the first element is a set of encoders that can be called in any order 
				# but have to be called before the 2nd set, etc.)
				#
				# This way encoders are ordered from first (eg. deepest level) to last (eg. top-level encapsulator)

				ordering = []
				
				for k in t:
					ordering.append(c[k][0])

				return self.order_chain(evasion_chain, ordering)
			except ValueError as err:
				# If we have a cyclic dependency we try the next candidate
				continue

		raise Exception("[-]No suitable dependency resolution could be found for evasion chain")
		return False