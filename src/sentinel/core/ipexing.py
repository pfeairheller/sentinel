# -*- encoding: utf-8 -*-

"""
Echelon Server
echelon_server.app.credentialing package

"""
import json
from typing import Optional
from urllib.parse import urlparse

import requests

from keri import help
from keri.app import signing
from keri.core import coring, eventing, parsing, routing
from keri.vdr import eventing as teventing
from keri.core.coring import Seqner
from keri.core.serdering import SerderKERI
from keri.db.dbing import dgKey
from keri.help import helping
from keri.kering import Ilks
from keri.peer import exchanging
from keri.vdr import verifying

from sentinel.core.chain_validator import ChainValidator
from sentinel.core.roots_of_trust import RootsOfTrustConfig

logger = help.ogler.getLogger()



def create_extended_ipex_grant(hby, hab, rgy, credential_said: str, recipient_aid: str, message: Optional[str] = None):
    creder, prefixer, seqner, saider = rgy.reger.cloneCred(said=credential_said)
    if not creder:
        raise ValueError(f"Invalid credential said: {credential_said}")

    schemer = hby.db.schema.get(keys=(creder.schema,))
    print(f"{schemer.sed.get("title")}: {creder.issuer}")

    message = message or ""
    grant_body = dict(
        m=message,
        d=creder.said,
        i=recipient_aid,
        pd=percolated_discovery(hby, rgy, creder, None, "->")
    )

    print(json.dumps(grant_body.get("pd"), indent=2))

    acdc = signing.serialize(creder, prefixer, seqner, saider)

    embeds = dict(
        acdc=acdc,
    )

    dt = helping.nowIso8601()

    exn, end = exchanging.exchange(route="/ipex/grant/ex", payload=grant_body, sender=hab.pre, embeds=embeds, date=dt)
    ims = hab.endorse(serder=exn, last=False, pipelined=False)
    del ims[:exn.size]
    ims.extend(end)

    return exn, ims

def percolated_discovery(hby, rgy, creder, edges: Optional[dict] = None, sep="->"):
    edges = edges or dict()
    oobi = get_issuer_oobi(hby, creder)

    edges[creder.said] = dict(
        i=creder.issuer,
        o=oobi
    )

    creder_edges = creder.edge or {}
    for key, value in creder_edges.items():
        if key == "d":
            continue

        if isinstance(value, dict) and "n" in value:
            credential_said = value["n"]
            edge_creder, *_ = rgy.reger.cloneCred(said=credential_said)
            if not edge_creder:
                continue

            schemer = hby.db.schema.get(keys=(edge_creder.schema,))
            print(f"{sep}{schemer.sed.get("title")}: {edge_creder.issuer}")

            edges = percolated_discovery(hby, rgy, edge_creder, edges, sep=f"{sep}->")

    return edges

def get_issuer_anchor(rgy, creder) -> str:
    registry_said = creder.regi
    status = rgy.reger.tevers[registry_said].vcState(creder.said)

    sn = 0 if status.et in [Ilks.iss, Ilks.bis] else 1
    tele = bytearray(rgy.reger.cloneTvtAt(creder.said, sn=sn))
    tserder = SerderKERI(raw=tele)
    vcid = tserder.ked["i"]
    regd = tserder.said
    key = dgKey(vcid, regd)
    sealet = rgy.reger.getAnc(key)
    seqner = Seqner(qb64b=sealet)
    return seqner.snh

def get_issuer_oobi(hby, creder) -> Optional[str]:
    issuer = creder.issuer
    for (key,), obr in hby.db.roobi.getItemIter():
        if obr.cid == issuer:
            return key

    return f"https://palantir.healthkeri.net/oobi/{issuer}"

class IpexExtendedGrantHandler:

    """
    Handler for essr encoded `exn` messages used to secure other messages intended for another recipient.
    This handler verifies the signer is correctly encryped in the payload and that the recipient was signed

    on
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "d": "EAhDiMFIINHBIn139nSG7QlNj7Sa2YHdZDIvzRYylQeE",
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/essr/req",
           "q": {
            }
           "a": '{
              "d": "6AA-AABWcUNwTFZON3I4WV9tV1VRSDFpWS10WW5RMjVFb3V4SWtheGxHZHRreWdRM1oxYzVx...",
              "i": "EAhDiMFIINHBIn139nSG7QlNj7Sa2YHdZDIvzRYylQeE"
           }
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/essr/req"

    def __init__(self, hby, hab, rgy, params=None, roots_config: Optional[RootsOfTrustConfig] = None):
        """
        Initializes an instance of the class with the provided parameters.

        Args:
            hby: Habery instance
            hab: Hab instance
            rgy: Regery instance
            params: Optional additional parameters
            roots_config: Optional roots of trust configuration for chain validation
        """
        self.hby = hby
        self.hab = hab
        self.rgy = rgy
        self.rtr = routing.Router()
        self.rvy = routing.Revery(
            db=self.hby.db, rtr=self.rtr, lax=True, local=True
        )
        self.kvy = eventing.Kevery(db=self.hby.db, lax=True, local=False, rvy=self.rvy)
        self.kvy.registerReplyRoutes(self.rtr)
        self.tvy = teventing.Tevery(db=self.hby.db, reger=self.rgy.reger)
        self.tvy.registerReplyRoutes(self.rtr)
        self.vry = verifying.Verifier(hby=self.hby, reger=self.rgy.reger)

        self.psr = parsing.Parser(framed=True, kvy=self.kvy, tvy=self.tvy, vry=self.vry, rvy=self.rvy)

        self.params = params or {}
        self.roots_config = roots_config
        self.chain_validator = ChainValidator(hby, rgy, roots_config) if roots_config else None

    def handle(self, serder, attachments=None, essr=None):
        """

        This handler decrypts the the encrypted payload, verifies that the sender is in the encrypted payload
        and verifies that the recipient AID was signed as part of the package

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event
            essr (bytes):  essr attached bytes

        """
        grant, pathed = exchanging.cloneMessage(self.hby, serder.said)
        if grant is None:
            raise ValueError(f"exn message said={serder.said} not found")

        route = grant.ked['r']
        if route != "/ipex/grant":
            raise ValueError(f"exn said={serder.said} is not a grant message, route={route}")

        pd = grant.get("a", {}).get("pd", None)
        if not pd:
            raise ValueError(f"exn said={serder.said} does not contain a pd attribute for percolated discovery")

        self.process_percolated_discovery(pd)

        # Validate credential chain against roots of trust
        if self.chain_validator:
            credential_said = grant.get("a", {}).get("d")
            if credential_said:
                results = self.chain_validator.validate_credential(credential_said)
                if results:
                    # Check if at least one root of trust validated successfully
                    valid_results = [r for r in results if r.valid]
                    if not valid_results:
                        # All validations failed, log details and raise error
                        error_details = []
                        for result in results:
                            errors = [f"  - {e.message}" for e in result.errors]
                            error_details.append(
                                f"Root '{result.root_id}' ({result.root_title}):\n" + "\n".join(errors)
                            )
                        error_msg = (
                            f"Credential {credential_said} failed validation against all "
                            f"applicable roots of trust:\n" + "\n".join(error_details)
                        )
                        logger.error(error_msg)
                        raise ValueError(error_msg)
                    else:
                        # Log successful validation
                        for result in valid_results:
                            logger.info(
                                f"Credential {credential_said} validated successfully against "
                                f"root '{result.root_id}' ({result.root_title})"
                            )
        return
        embeds = grant.ked['e']
        acdc = embeds["acdc"]

        for label in ("anc", "reg", "iss", "acdc"):
            ked = embeds[label]
            sadder = coring.Sadder(ked=ked)
            ims = bytearray(sadder.raw) + pathed[label]
            self.psr.parseOne(ims=ims)

        credential_said = acdc["d"]
        if not self.rgy.reger.saved.get(keys=credential_said):
            raise ValueError(f"Credential said={credential_said} did not parse from message said={serder.said}")


    def process_percolated_discovery(self, pd: dict):
        """
        Process the percolated discovery field from bottom to top of the credential chain.

        For each credential SAID in the pd field (processed in reverse order):
        1. Check if the credential is already in the database
        2. If not, resolve the OOBI to get the issuer's key state
        3. Verify the issuer AID is in kevers
        4. Find the registrar endpoint and fetch the credential
        5. Parse and save the credential

        Parameters:
            pd: Dictionary mapping credential SAIDs to issuer info with "i" (issuer AID) and "o" (OOBI URL)

        Raises:
            ValueError: If any credential cannot be resolved or parsed
        """
        credential_saids = list(pd.keys())
        credential_saids.reverse()

        for credential_said in credential_saids:
            if self.rgy.reger.saved.get(keys=(credential_said,)):
                logger.info(f"Credential {credential_said} already in database, skipping")
                continue

            issuer_info = pd[credential_said]
            issuer_aid = issuer_info["i"]
            oobi_url = issuer_info["o"]

            print("Resolving OOBI URL:", oobi_url)

            response = requests.get(oobi_url)
            if response.status_code != 200:
                raise ValueError(f"Failed to resolve OOBI {oobi_url} for credential {credential_said}: status {response.status_code}")

            self.psr.parse(ims=bytearray(response.content))
            self.kvy.processEscrows()

            if issuer_aid not in self.hby.kevers:
                raise ValueError(f"Issuer AID {issuer_aid} not found in kevers after resolving OOBI {oobi_url}")

            registrar_url = self._get_registrar_url(issuer_aid, oobi_url)
            if not registrar_url:
                raise ValueError(f"No registrar endpoint found for issuer {issuer_aid}")

            credential_url = f"{registrar_url.rstrip('/')}/oobi/{credential_said}"
            cred_response = requests.get(credential_url)
            if cred_response.status_code != 200:
                raise ValueError(f"Failed to fetch credential {credential_said} from {credential_url}: status {cred_response.status_code}")

            self.psr.parse(ims=bytearray(cred_response.content))
            self.kvy.processEscrows()
            self.tvy.processEscrows()
            self.vry.processEscrows()

            if not self.rgy.reger.saved.get(keys=(credential_said,)):
                raise ValueError(f"Credential {credential_said} failed to parse from {credential_url}")

            logger.info(f"Successfully loaded credential {credential_said} from chain")

    def _get_registrar_url(self, issuer_aid: str, oobi_url: str) -> Optional[str]:
        """
        Find the registrar endpoint URL for a given issuer AID.

        First checks the location endpoint records for the "registrar" role of the issuer.
        Falls back to extracting the base URL from the OOBI URL if no location record is found.

        Parameters:
            issuer_aid: The AID of the issuer to find the registrar endpoint for
            oobi_url: The OOBI URL used to resolve the issuer (fallback source)

        Returns:
            The registrar URL if found, None otherwise
        """
        ends = self.hab.endsFor(issuer_aid)
        if not "registrar" in ends:
            return None

        registrar = ends["registrar"]
        for aid, locs in registrar.items():
            if "https" in locs:
                return locs["https"]

        return None