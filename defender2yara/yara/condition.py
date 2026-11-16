from typing import List,Dict,Union

import logging
from defender2yara.defender.signature.hstr import HStrSig,HStrExtSig

from .strings import YaraString

logger = logging.getLogger(__package__)

# Guard rails for generate_subsets(). Some signatures - "!InfrastructureShared" for example -
# have thousands of distinct positive weights, so the number of minimal subsets meeting the
# threshold is astronomically large (10^9+). Enumerating them is neither expressible in a YARA
# condition nor feasible: it burns CPU and memory indefinitely.
DEFAULT_MAX_SUBSET_NODES = 2_000_000
DEFAULT_MAX_SUBSET_BRANCHES = 10_000
DEFAULT_MAX_CONDITION_BYTES = 2_000_000
# Estimated binary size of a single OR branch, used to bound the generated condition.
_BRANCH_BYTES_ESTIMATE = 40


class SubsetBudgetExceeded(Exception):
    """Raised when the minimal subset search for a signature exceeds its node budget."""


class YaraCondition:
    def __init__(self,strings:List[YaraString],signature:Union[HStrSig,HStrExtSig],filesize_check:str,do_header_check:bool=False):
        self.threshold = signature.threshold
        self.strings = strings
        self.signature = signature
        self.do_header_check = do_header_check
        self.filesize_check = filesize_check
        self.statements:List[Union[str,List[str]]] = [] # all state is connected with "and"
        # True if the threshold could not be expressed and a simplified condition was used.
        self.fallback:bool = False
        self.compose_logical_expression()

    def compose_logical_expression(self):
        # add filesize check to improve the scan performance
        if self.filesize_check:
            self.statements.append(f"filesize < {self.filesize_check}")

        # add file header check to improve the scan performance
        if self.do_header_check:
            if "PEHSTR" in self.signature.sig_type or "DOSHSTR" in self.signature.sig_type:
                self.statements.append("uint16(0) == 0x5a4d")
            elif "MACHOHSTR" in self.signature.sig_type:
                self.statements.append(
                    "(uint32(0) == 0xfeedfacf) or "
                    "(uint32(0) == 0xcffaedfe) or "
                    "(uint32(0) == 0xfeedface) or "
                    "(uint32(0) == 0xcefaedfe)"
                ) 
            elif "ELFHSTR" in self.signature.sig_type:
                self.statements.append("uint32(0) == 0x464c457f")

        # Score each subrule once on presence, not once per occurrence. Signed
        # arithmetic preserves negative weights without exponential subsets.
        terms = []
        for index, string in enumerate(self.strings, 1):
            prefix = "x" if string.weight > 0 else "n"
            identifier = f"${prefix}_{abs(string.weight)}_{index}"
            terms.append(f"({string.weight}) * math.to_number({identifier})")
        score = " + ".join(terms) if terms else "0"
        self.statements.append(f"({score}) >= {self.threshold}")

    
    @staticmethod
    def generate_subsets(
        weight_map: Dict[int, int],
        threshold: int,
        max_nodes: int = DEFAULT_MAX_SUBSET_NODES,
        max_branches: int = DEFAULT_MAX_SUBSET_BRANCHES,
    ) -> List[List[int]]:
        """
        Generate the subsets of weights that meet or exceed the given threshold, 
        without including supersets of already valid subsets.

        This function uses a backtracking algorithm to generate the minimal subsets
        of weights from the given weight map, where the sum of weights in each subset
        is greater than or equal to the specified threshold. It includes all minimal
        subsets that meet the threshold, but excludes any superset of an already 
        included subset.

        The search is bounded: it raises SubsetBudgetExceeded once it has visited
        max_nodes nodes or produced max_branches subsets. Pathological signatures can
        have more than 10^9 minimal subsets, which can not be enumerated (let alone
        compiled into a YARA condition), so callers must handle this exception.

        Args:
            weight_map (Dict[int, int]): A dictionary mapping weights to their counts.
            threshold (int): The minimum sum of weights required for a valid subset.
            max_nodes (int): Maximum number of explored nodes before aborting.
            max_branches (int): Maximum number of subsets before aborting.

        Returns:
            List[List[int]]: A list of all valid subsets, where each subset is 
                            represented as a list of weights. If a subset meets the
                            threshold, no superset of it will be included in the result.

        Raises:
            SubsetBudgetExceeded: If the search exceeds max_nodes or max_branches.

        Example:
            >>> weight_map = {5: 2, 3: 1, 2: 2, 1: 1}
            >>> threshold = 7
            >>> generate_subsets(weight_map, threshold)
            [[5, 5], [5, 3], [5, 2, 2]]
            # Note: [5, 5, 1] is not included as [5, 5] already meets the threshold
        """
        # Get lists of keys (weights) and values (counts) from the dictionary
        weight_values = list(weight_map.keys())
        weight_counts = list(weight_map.values())

        def backtrack(index: int, current_subset: List[int], subsets: List[List[int]]):
            """
            Helper function to generate all subsets using backtracking with pruning.

            This function implements a depth-first search with backtracking to generate
            all valid subsets. It uses two key pruning strategies to optimize the search:

            1. Early termination: If the current subset sum meets or exceeds the threshold,
            we add it to the result (if valid) and stop exploring further additions.

            2. Subset pruning: If we find a valid subset, we skip adding any elements
            that would create a superset of an already valid subset. This prevents
            generating redundant supersets.

            Args:
                index (int): Current index in the weight_values list.
                current_subset (List[int]): The current subset being built.
                subsets (List[List[int]]): List to store all valid subsets.

            Raises:
                SubsetBudgetExceeded: If the search exceeds max_nodes or max_branches.

            Note:
                The function modifies the 'subsets' list in-place to collect valid subsets.
                It uses recursion to explore all possible combinations of weights.
            """
            nonlocal nodes_visited
            nodes_visited += 1
            if nodes_visited > max_nodes or len(subsets) > max_branches:
                raise SubsetBudgetExceeded(
                    f"subset search exceeded budget: nodes={nodes_visited}, subsets={len(subsets)}"
                )

            # If the sum of the current subset meets or exceeds the threshold
            if sum(current_subset) >= threshold:
                # Don't add if a subset that sums to the threshold has already been found
                if sum(current_subset) - current_subset[-1] >= threshold:
                    return
                subsets.append(current_subset.copy())
                return

            # If we've reached the end of the weight list, return
            if index == len(weight_values):
                return

            # Case 1: Don't include the current weight
            backtrack(index + 1, current_subset, subsets)

            # Case 2: Include the current weight (up to its count)
            for _ in range(weight_counts[index]):
                current_subset.append(weight_values[index])
                backtrack(index + 1, current_subset, subsets)

            # Restore the original state (backtrack)
            for _ in range(weight_counts[index]):
                current_subset.pop()

        # List to store all valid subsets
        nodes_visited = 0
        all_subsets = []
        backtrack(0, [], all_subsets)
        return all_subsets