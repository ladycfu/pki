# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
from contextlib import contextmanager

from pki.server.healthcheck.certs.plugin import CertsPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

logger = logging.getLogger(__name__)


@registry
class CASystemCertTrustFlagCheck(CertsPlugin):
    """
    Compare the NSS trust for the CA certs to a known good value
    """
    @duration
    def check(self):

        if not self.instance.exists():
            logger.debug('Invalid instance: %s', self.instance.name)
            yield Result(self, constants.CRITICAL,
                         msg='Invalid PKI instance: %s' % self.instance.name)
            return

        self.instance.load()

        # Make a list of known good trust flags for ALL system certs
        expected_trust = {
            'signing': 'CTu,Cu,Cu',
            'ocsp_signing': 'u,u,u',
            'audit_signing': 'u,u,Pu',
            'sslserver': 'u,u,u',
            'subsystem': 'u,u,u'
        }

        ca = self.instance.get_subsystem('ca')

        if not ca:
            logger.debug("No CA configured, skipping CA System Cert Trust Flag check")
            return

        certs = ca.find_system_certs()

        # Iterate on CA's all system certificate to check with list of expected trust flags
        for cert in certs:
            cert_id = cert['id']

            # Load cert trust from NSSDB
            with nssdb_connection(self.instance) as nssdb:
                try:
                    cert_trust = nssdb.get_trust(
                        nickname=cert['nickname'],
                        token=cert['token']
                    )
                except Exception as e:  # pylint: disable=broad-except
                    logger.debug('Unable to load cert from NSSDB: %s', str(e))
                    yield Result(self, constants.ERROR,
                                 key=cert_id,
                                 nssdbDir=self.instance.nssdb_dir,
                                 msg='Unable to load cert from NSSDB: %s' % str(e))
                    continue
            if cert_trust != expected_trust[cert_id]:
                yield Result(self, constants.ERROR,
                             cert_id=cert_id,
                             nickname=cert['nickname'],
                             token=cert['token'],
                             cert_trust=cert_trust,
                             msg='Incorrect NSS trust for %s. Got %s expected %s'
                             % (cert['nickname'], cert_trust, expected_trust[cert_id]))
            else:
                yield Result(self, constants.SUCCESS,
                             cert_id=cert_id,
                             nickname=cert['nickname'])


@contextmanager
def nssdb_connection(instance):
    """Open a connection to nssdb containing System Certificates"""
    nssdb = instance.open_nssdb()
    try:
        yield nssdb
    finally:
        nssdb.close()