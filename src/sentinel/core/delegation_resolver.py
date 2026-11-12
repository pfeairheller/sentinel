# -*- encoding: utf-8 -*-
"""
sentinel.core.delegation_resolver module

Resolves KERI delegation chains for credential issuer validation.

"""

from typing import List, Optional

from keri import help

logger = help.ogler.getLogger()


class DelegationResolver:
    """
    Resolves KERI delegation chains for validating credential issuers.

    This class traverses the delegation hierarchy of KERI AIDs to determine
    if an issuer is authorized through delegation relationships.

    Example:
        resolver = DelegationResolver(hby)
        chain = resolver.get_delegation_chain(aid)
        is_delegated = resolver.is_delegated_by(aid, delegator, transitive=True)
    """

    def __init__(self, hby):
        """
        Initialize the DelegationResolver.

        Args:
            hby: The Habery instance containing kevers for AID lookup
        """
        self.hby = hby

    def get_immediate_delegator(self, aid: str) -> Optional[str]:
        """
        Get the immediate delegator of an AID.

        Args:
            aid: The AID to find the delegator for

        Returns:
            The delegator AID if this is a delegated identifier, None otherwise
        """
        if aid not in self.hby.kevers:
            logger.warning(f"DelegationResolver: AID {aid} not found in kevers")
            return None

        kever = self.hby.kevers[aid]

        # Check if this is a delegated identifier
        # Delegated identifiers have a "di" (delegator identifier) field in their inception event
        if hasattr(kever, "delpre") and kever.delpre:
            return kever.delpre

        return None

    def get_delegation_chain(self, aid: str) -> List[str]:
        """
        Get the full delegation chain for an AID, from the AID up to the root.

        Args:
            aid: The AID to find the delegation chain for

        Returns:
            List of AIDs in the delegation chain, starting with the given AID
            and ending with the root (non-delegated) AID.
            Returns [aid] if the AID is not delegated.
        """
        chain = [aid]
        current = aid
        visited = {aid}  # Prevent infinite loops

        while True:
            delegator = self.get_immediate_delegator(current)
            if delegator is None:
                break

            if delegator in visited:
                logger.warning(
                    f"DelegationResolver: Circular delegation detected at {delegator}"
                )
                break

            chain.append(delegator)
            visited.add(delegator)
            current = delegator

        return chain

    def is_delegated_by(
        self, aid: str, delegator: str, transitive: bool = False
    ) -> bool:
        """
        Check if an AID is delegated by a specific delegator.

        Args:
            aid: The AID to check
            delegator: The potential delegator AID
            transitive: If True, check the entire delegation chain;
                       if False, only check immediate delegation

        Returns:
            True if the delegator relationship exists, False otherwise
        """
        if aid == delegator:
            return True

        if transitive:
            # Check the entire delegation chain
            chain = self.get_delegation_chain(aid)
            return delegator in chain
        else:
            # Only check immediate delegator
            immediate = self.get_immediate_delegator(aid)
            return immediate == delegator

    def is_delegated(self, aid: str) -> bool:
        """
        Check if an AID is a delegated identifier.

        Args:
            aid: The AID to check

        Returns:
            True if the AID is delegated, False otherwise
        """
        return self.get_immediate_delegator(aid) is not None

    def get_root_delegator(self, aid: str) -> str:
        """
        Get the root (non-delegated) AID in the delegation chain.

        Args:
            aid: The AID to find the root for

        Returns:
            The root AID (which may be the same as the input if not delegated)
        """
        chain = self.get_delegation_chain(aid)
        return chain[-1] if chain else aid
