

# This work was created by participants in the DataONE project, and is
# jointly copyrighted by participating institutions in DataONE. For
# more information on DataONE, see our web site at http://dataone.org.
#
#   Copyright 2009-2019 DataONE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Extract subjects from a DataONE X.509 v3 certificate.

If a certificate was provided, it has been validated by Apache before being
passed to GMN. So it is known to signed by a trusted CA and to be unexpired.

A user can connect without providing a certificate (and so, without providing a
session). This limits the user's access to data that is publicly available.

A user can connect with a certificate that does not contain a list of
equivalent identities and group memberships (no SubjectInfo). This limits the
user's access to data that is publicly available and that is available directly
to that user (as designated in the Subject DN).

"""

import d1_common.cert.subjects
import d1_common.const
import d1_common.types.exceptions

from urllib.parse import unquote


# The WSGI/environment made available via Apache's SSLOptions +ExportCertData
#
# Example Apache config fragement:
#
#   <Files "wsgi.py">
#       SSLOptions +ExportCertData
#   </Files>
SSL_CLIENT_CERT='SSL_CLIENT_CERT'

# The HTTP header made available via nginx (X-SSL-Client-Cert)
#
# Example nginx config fragement, using proxy_pass reverse proxy to a gunicorn
# wsgi wrapper, and passing the X-SSL-Client-Cert HTTP header with the escaped
# contents of the client cert
#
#   location /mn/ {
#       proxy_pass          http://django_gunicorn:8000/;
#       proxy_set_header    X-Real-IP $remote_addr;
#       proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
#       proxy_set_header    Host    $host;
#       proxy_set_header    X-Forwarded-Proto   $scheme;
#       proxy_set_header    X-SSL-Client-Cert $ssl_client_escaped_cert;
#       proxy_redirect  off;
#       # proxy_ssl_server_name on;
#   }
#
HTTP_X_SSL_CLIENT_CERT='HTTP_X_SSL_CLIENT_CERT'

SSL_CLIENT_CERT_META_KEYS=(
    SSL_CLIENT_CERT,
    HTTP_X_SSL_CLIENT_CERT,
)

def _which_ssl_client_cert_meta( request_meta ):
    """Attempt a few known keys in request.META known to be available via """
    """Apache, nginx (and other) HTTP/WSGI frontends."""

    assert isinstance( request_meta, dict )

    for k in SSL_CLIENT_CERT_META_KEYS:

        if k in request_meta:
            return k

    return None


def get_subjects(request):
    """Get all subjects in the certificate.

    - Returns: primary_str (primary subject), equivalent_set (equivalent identities,
      groups and group memberships)
    - The primary subject is the certificate subject DN, serialized to a DataONE
      compliant subject string.

    """
    if _is_certificate_provided(request):
        try:
            k = _which_ssl_client_cert_meta( request.META )
            if k is None:
                raise Exception(
                    'No known client SSL cert key present in request.META: '
                    f'{",".SSL_CLIENT_CERT_META_KEYS}'
                )
            return get_authenticated_subjects(request.META[k])
        except Exception as e:
            raise d1_common.types.exceptions.InvalidToken(
                0,
                'Error extracting session from certificate. error="{}"'.format(str(e)),
            )
    else:
        return d1_common.const.SUBJECT_PUBLIC, set()


def get_authenticated_subjects(cert_pem):
    """Return primary subject and set of equivalents authenticated by certificate.

    - ``cert_pem`` can be str or bytes

    """
    if isinstance(cert_pem, str):

        if '%20' in cert_pem:
            # This cert is likely '%xx' encoded, and needs to be unquoted in
            # order to be able to extract the subject.
            cert_pem = unquote( cert_pem )

        cert_pem = cert_pem.encode("utf-8")

    return d1_common.cert.subjects.extract_subjects(cert_pem)


def _is_certificate_provided(request):

    k = _which_ssl_client_cert_meta( request.META )

    if k is None:
        return False

    return k in request.META and request.META[k] != ""
