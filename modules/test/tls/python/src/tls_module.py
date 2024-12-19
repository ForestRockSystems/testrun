# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""TLS test module"""
# pylint: disable=W0212

from test_module import TestModule
from tls_util import TLSUtil
import os
import pyshark
from binascii import hexlify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.x509 import AuthorityKeyIdentifier, SubjectKeyIdentifier, BasicConstraints, KeyUsage
from cryptography.x509 import GeneralNames, DNSName, ExtendedKeyUsage, ObjectIdentifier, SubjectAlternativeName
from jinja2 import Environment, FileSystemLoader

LOG_NAME = 'test_tls'
MODULE_REPORT_FILE_NAME = 'tls_report.html'
STARTUP_CAPTURE_FILE = '/runtime/device/startup.pcap'
MONITOR_CAPTURE_FILE = '/runtime/device/monitor.pcap'
TLS_CAPTURE_FILE = '/runtime/output/tls.pcap'
GATEWAY_CAPTURE_FILE = '/runtime/network/gateway.pcap'
LOGGER = None
REPORT_TEMPLATE_FILE = 'report_template.jinja2'

HTML = '''<html><head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">
  <title>
   Testrun Report
  </title>
  <style>
   /* Set some global variables */
    :root {
      --header-height: .75in;
      --header-width: 8.5in;
      --header-pos-x: 0in;
      --header-pos-y: 0in;
      --page-width: 8.5in;
      --summary-height: 2.8in;
      --vertical-line-height: calc(var(--summary-height)-.2in);
      --vertical-line-pos-x: 25%;
    }

    @font-face {
      font-family: 'Google Sans';
      font-style: normal;
      src: url(https://fonts.gstatic.com/s/googlesans/v58/4Ua_rENHsxJlGDuGo1OIlJfC6l_24rlCK1Yo_Iqcsih3SAyH6cAwhX9RFD48TE63OOYKtrwEIJllpyk.woff2) format('woff2');
      unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
    }

    @font-face {
      font-family: 'Roboto Mono';
      font-style: normal;
      src: url(https://fonts.googleapis.com/css2?family=Roboto+Mono:ital,wght@0,100..700;1,100..700&display=swap) format('woff2');
      unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
    }

    /* Define some common body formatting*/
    body {
      font-family: 'Google Sans', sans-serif;
      margin: 0;
      padding: 0;
    }

    /* Use this for various section breaks*/
    .gradient-line {
      position: relative;
      background-image: linear-gradient(to right, red, blue, green, yellow, orange);
      height: 1px;
      /* Adjust the height as needed */
      width: 100%;
      /* To span the entire width */
      display: block;
      /* Ensures it's a block-level element */
    }

    /* Sets proper page size during print to pdf for weasyprint */
    @page {
      size: Letter;
      width: 8.5in;
      height: 11in;
    }

    .page {
      position: relative;
      margin: 0 20px;
      width: 8.5in;
      height: 11in;
    }

    /* Define the  header related css elements*/
    .header {
      position: relative;
      border-bottom: 1px solid #DADCE0;
      padding-bottom: 20px;
    }

    .header.first-page {
      border-bottom: none;
    }

    .header-info {
      max-width: 600px;
      box-sizing: border-box;
      display: flex;
      align-items: center;
      margin-bottom: 8px;
      color: #202124;
      font-size: 9px;
      text-transform: uppercase;
    }

    .first-page .header-info {
      font-size: 18px;
    }

    .header-info .header-info-badge {
      margin-right: 8px;
    }

    .first-page .header-info .header-info-badge {
      margin-right: 16px;
    }

    .header-info-badge {
      align-items: center;
      margin: 0;
      padding: 5px 15px;
      border: 1px solid #202124;
      border-radius: 4px;
      font-weight: 500;
      letter-spacing: 0.64px;
      box-sizing: border-box;
    }

    .first-page .header-info-badge {
      padding: 15px 30px;
      letter-spacing: 1px;
    }

    .header-info-badge img {
      width: 9px;
      height: 9px;
      margin-right: 10px;
    }

    .first-page .header-info-badge img {
      width: 16px;
      height: 16px;
    }

    .header-info h1 {
      margin: 0;
      font-size: 9px;
      font-weight: 700;
      letter-spacing: 0.1px;
    }

    .first-page .header-info h1 {
      font-size: 18px;
      letter-spacing: 1px;
    }

    .header-info-device {
      margin-top: 0;
      max-width: 700px;
      margin-bottom: 24px;
      font-size: 24px;
      font-weight: bold;
    }

    .first-page .header-info-device {
      margin: 0;
      font-size: 48px;
      font-weight: 700;
    }

    h1 {
      margin: 0 0 8px 0;
      font-size: 20px;
      font-weight: 400;
    }

    h2 {
      margin: 0;
      font-size: 48px;
      font-weight: 700;
    }

    h3 {
      font-size: 24px;
    }

    h4 {
      font-size: 12px;
      font-weight: 500;
      color: #5F6368;
      margin-bottom: 0;
      margin-top: 0;
    }

    .module-summary {
      background-color: #F8F9FA;
      width: 100%;
      margin-bottom: 25px;
    }

    .module-summary.not-first{
      margin-top: 10px;
    }


    .module-summary thead tr th {
      text-align: left;
      padding-top: 15px;
      padding-left: 10px;
      padding-right: 5px;
      font-weight: 500;
      color: #5F6368;
      font-size: 14px;
    }

    .module-summary tbody tr td {
      padding-bottom: 15px;
      padding-left: 10px;
      padding-right: 5px;
      font-size: 22px;
    }

    .module-data {
      border: 1px solid #DADCE0;
      border-radius: 3px;
      border-spacing: 0;
    }

    .module-data thead tr th {
      text-align: left;
      padding: 12px 25px;
      color: #3C4043;
      font-size: 14px;
      font-weight: 700;
    }

    .module-data tbody tr td {
      text-align: left;
      padding: 12px 25px;
      color: #3C4043;
      font-size: 14px;
      font-weight: 400;
      border-top: 1px solid #DADCE0;
      font-family: 'Roboto Mono', monospace;
      word-wrap: break-word;
      word-break: break-word;
    }

    div.steps-to-resolve {
      background-color: #F8F9FA;
      margin-bottom: 30px;
      width: 756px;
      padding: 20px 30px;
      vertical-align: top;
    }

    .steps-to-resolve-row {
      vertical-align: top;
    }

    .steps-to-resolve-row.content {
      margin-left: 70px;
    }

    .steps-to-resolve-test-name {
      display: inline-block;
      margin-left: 70px;
      margin-right: 10px;
      margin-bottom: 20px;
      width: 250px;
      vertical-align: top;
    }

    .steps-to-resolve-description {
      display: inline-block;
    }

    .steps-to-resolve.subtitle {
      text-align: left;
      padding-top: 15px;
      font-weight: 500;
      color: #5F6368;
      font-size: 14px;
    }
  
    .steps-to-resolve-index {
      font-size: 40px;
      position: absolute;
      margin-left: 10px;
    }

    .callout-container.info {
      background-color: #e8f0fe;
    }

    .callout-container.info .icon {
      width: 22px;
      height: 22px;
      margin-right: 10px;
      background-size: contain;
      background-image: url('data:image/png;base64,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');
    }

    .callout-container {
      display: flex;
      box-sizing: border-box;
      height: auto;
      min-height: 48px;
      padding: 6px 24px;
      border-radius: 8px;
      align-items: center;
      color: #3c4043;
      font-size: 14px;
    }

    .device-information {
      padding-top: 0.2in;
      padding-left: 0.2in;
      background-color: #F8F9FA;
      width: 250px;
      height: 100.4%;
    }

    /* Define the summary related css elements*/
    .summary-content {
      position: relative;
      width: var(--page-width);
      height: var(--summary-height);
      margin-top: 19px;
      margin-bottom: 19px;
      background-color: #E8EAED;
      padding-bottom: 20px;
    }

    .summary-item-label {
      position: relative;
    }

    .summary-item-value {
      position: relative;
      font-size: 20px;
      font-weight: 400;
      color: #202124;
    }

    .summary-item-space {
      position: relative;
      padding-bottom: 15px;
      margin: 0;
    }

    .summary-device-modules {
      position: absolute;
      left: 3.2in;
      top: .2in;
    }

    .summary-device-module-label {
      font-size: 16px;
      font-weight: 500;
      color: #202124;
      width: fit-content;
      margin-bottom: 0.1in;
    }

    .summary-vertical-line {
      width: 1px;
      height: var(--vertical-line-height);
      background-color: #80868B;
      position: absolute;
      top: .3in;
      bottom: .1in;
      left: 3in;
    }

    /* CSS for the color box */
    .summary-color-box {
      position: absolute;
      right: 0;
      top: 0;
      width: 2.6in;
      height: 100%;
    }

    .summary-box-compliant {
      background-color: rgb(24, 128, 56);
    }

    .summary-box-non-compliant {
      background-color: #b31412;
    }

    .summary-box-label {
      font-size: 14px;
      margin-top: 5px;
      color: #DADCE0;
      position: relative;
      top: 10px;
      left: 20px;
      font-weight: 500;
    }

    .summary-box-value {
      font-size: 18px;
      margin: 0 0 10px 0;
      color: #ffffff;
      position: relative;
      top: 10px;
      left: 20px;
    }

    .result-list-title {
      font-size: 24px;
      color: black;
    }

    .result-list {
      position: relative;
      margin-top: .2in;
      font-size: 18px;
    }

    .result-list h3,
    .page-heading {
      margin: 0.2in 0;
      font-size: 30px;
      font-weight: normal;
      color: black;
    }

    .result-line {
      border: 1px solid #D3D3D3;
      /* Light Gray border*/
      height: .4in;
      width: 8.5in;
    }

    .result-line-result {
      border-top: 0;
    }

    .result-list-header-label {
      position: absolute;
      font-size: 12px;
      font-weight: bold;
      height: 40px;
      display: flex;
      align-items: center;
    }

    .result-test-label {
      position: absolute;
      font-size: 12px;
      margin-top: 12px;
      max-width: 300px;
      font-weight: normal;
      align-items: center;
      text-overflow: ellipsis;
      white-space: nowrap;
      overflow: hidden;
    }

    .result-test-description {
      max-width: 380px;
    }

    .result-test-result-error {
      background-color: #FCE8E6;
      color: #C5221F;
    }

    .result-test-result-feature-not-detected {
      background-color: #e3e3e3;
    }

    .result-test-result-informational {
      background-color: #E0F7FA;
      color: #006064;
    }

    .result-test-result-non-compliant {
      background-color: #FCE8E6;
      color: #C5221F;
    }

    .result-test-result {
      position: absolute;
      font-size: 12px;
      width: fit-content;
      height: 12px;
      margin-top: 8px;
      padding: 4px 4px 7px 5px;
      border-radius: 2px;
      left: 6.85in;
    }

    .result-test-result-compliant {
      background-color: #E6F4EA;
      color: #137333;
    }

    .result-test-result-skipped {
      background-color: #e3e3e3;
      color: #393939;
    }

    /* CSS for the footer */
    .footer {
      position: absolute;
      height: 30px;
      width: 8.5in;
      bottom: 0;
      border-top: 1px solid #D3D3D3;
    }

    .footer-label {
      color: #3C4043;
      position: absolute;
      top: 5px;
      font-size: 12px;
    }

    /*CSS for the markdown tables */
    .markdown-table {
      border-collapse: collapse;
      margin-left: 20px;
      background-color: #F8F9FA;
    }

    .markdown-table th, .markdown-table td {
      border: none;
      text-align: left;
      padding: 8px;
    }

    .markdown-header-h1 {
      margin-top:20px;
      margin-bottom:20px;
      margin-right:0;
      font-size: 2em;
    }

    .markdown-header-h2 {
      margin-top: 20px;
      margin-bottom: 20px;
      margin-right: 0;
      font-size: 1.5em;
    }

    .module-page-content {
      /*Page height minus header(93px), footer(30px), 
      and a 20px bottom padding.*/
      height: calc(11in - 93px - 30px - 20px);
      /* In case we mess something up in our calculations
        we'll cut off the content of the page so 
        the header, footer and line break work
        as expected
      */
      overflow: hidden;
    }

    .module-page-content h1,
    .module-page-content h2 {
      padding-left: 0.2in;
      margin: 0.2in 0;
      font-size: 30px;
      font-weight: normal;
    }

    /* CSS for Device profile */
    .device-profile-content {
      width: 100%;
      margin-top: 40px;
      text-align: left;
      color: #3C4043;
      font-size: 14px;
    }

    .device-profile-head {
      margin-bottom: 15px;
    }

    .device-profile-head-question {
      display: inline-block;
      margin-left: 70px;
      font-weight: bold;
    }

    .device-profile-head-answer {
      display: inline-block;
      margin-left: 325px;
      font-weight: bold;
    }

    .device-profile-row {
      margin-bottom: 8px;
      background-color: #F8F9FA;
      display: flex;
      align-items: stretch;
      overflow: hidden;
    }

    .device-profile-number {
      padding: 15px 20px;
      width: 10px;
      display: inline-block;
      vertical-align: top;
      position: relative;
    }

    .device-profile-question {
      padding: 15px 20px;
      display: inline-block;
      width: 350px;
      vertical-align: top;
      position: relative;
      height: 100%;
    }

    .device-profile-answer {
      background-color: #E8F0FE;
      padding: 15px 20px;
      display: inline-block;
      width: 340px;
      position: relative;
      height: 100%;
    }

    .device-profile-answer ul {
      margin-top: 0;
      padding-left: 20px;
    }

    /* CSS for Steps to resolve to meet full device qualification in Pilot program */
    .steps-to-resolve-info {
      display: flex;
      flex-direction: column;
      margin: 30px 0;
      padding: 30px 45px;
      background: #E8F0FE;
      color: #174EA6;
    }

    .steps-to-resolve-info-heading {
      margin: 0 0 10px;
      font-size: 24px;
      font-weight: 500;
      line-height: 16px;
      letter-spacing: 0.64px;
      text-transform: uppercase;
    }

    .steps-to-resolve-info-content {
      margin: 0;
      font-size: 16px;
      line-height: normal;
      letter-spacing: 0.64px;
    }

    @media print {
      @page {
        size: Letter;
        width: 8.5in;
        height: 11in;
      }
    }
  </style>
 </head>
 <body>'''

class TLSModule(TestModule):
  """The TLS testing module."""

  def __init__(self,
               module,
               conf_file=None,
               results_dir=None,
               startup_capture_file=STARTUP_CAPTURE_FILE,
               monitor_capture_file=MONITOR_CAPTURE_FILE,
               tls_capture_file=TLS_CAPTURE_FILE):
    super().__init__(module_name=module,
                     log_name=LOG_NAME,
                     conf_file=conf_file,
                     results_dir=results_dir)
    self.startup_capture_file = startup_capture_file
    self.monitor_capture_file = monitor_capture_file
    self.tls_capture_file = tls_capture_file
    global LOGGER
    LOGGER = self._get_logger()
    self._tls_util = TLSUtil(LOGGER)

  def generate_module_report(self):
    # Load Jinja2 template
    page_max_height = 910
    header_height = 48
    summary_height = 135
    row_height = 42
    loader=FileSystemLoader(self._report_template_folder)
    template = Environment(loader=loader).get_template(REPORT_TEMPLATE_FILE)
    module_header='TLS Module'
    # Summary table headers
    summary_headers = [
                        'Expiry',
                        'Length',
                        'Type',
                        'Port number',
                        'Signed by',
                        ]
    # Cert table headers
    cert_table_headers = ['Property', 'Value']
    # Outbound connections table headers
    outbound_headers = ['Destination IP', 'Port']
    pages = {}
    html_content = '<h4 class="page-heading">TLS Module</h4>'

    # List of capture files to scan
    pcap_files = [
        self.startup_capture_file, self.monitor_capture_file,
        self.tls_capture_file
    ]
    certificates = self.extract_certificates_from_pcap(pcap_files,
                                                       self._device_mac)

    if len(certificates) > 0:

      cert_tables = []
      # pylint: disable=W0612
      for cert_num, ((ip_address, port),
                     cert) in enumerate(certificates.items()):
        pages[cert_num] = {}
        # Add summary table
        summary_table = '''
          <table class="module-summary" style="width:100%;">
            <thead>
              <tr>
                <th>Expiry</th>
                <th>Length</th>
                <th>Type</th>
                <th>Port number</th>
                <th>Signed by</th>
              </tr>
            </thead>
            <tbody>
          '''

        # Generate the certificate table
        cert_table = '''
          <table class="module-data">
            <thead>
              <tr>
                <th>Property</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>'''

        # Extract certificate data
        not_valid_before = cert.not_valid_before
        not_valid_after = cert.not_valid_after
        version_value = f'{cert.version.value + 1} ({hex(cert.version.value)})'
        signature_alg_value = cert.signature_algorithm_oid._name
        not_before = str(not_valid_before)
        not_after = str(not_valid_after)
        public_key = cert.public_key()
        signed_by = 'None'

        if isinstance(public_key, rsa.RSAPublicKey):
          public_key_type = 'RSA'
        elif isinstance(public_key, dsa.DSAPublicKey):
          public_key_type = 'DSA'
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
          public_key_type = 'EC'
        else:
          public_key_type = 'Unknown'

        # Calculate certificate length
        cert_length = len(
            cert.public_bytes(encoding=serialization.Encoding.DER))

        # Append certification information
        pages[cert_num]['cert_info_data'] = {
                            'Version': version_value,
                            'Signature Alg.': signature_alg_value,
                            'Validity from': not_before,
                            'Valid to': not_after,
                          }
        cert_table += f'''
          <tr>
            <td>Version</td>
            <td>{version_value}</td>
          </tr>
          <tr>
            <td>Signature Alg.</td>
            <td>{signature_alg_value}</td>
          </tr>
          <tr>
            <td>Validity from</td>
            <td>{not_before}</td>
          </tr>
          <tr>
            <td>Valid to</td>
            <td>{not_after}</td>
          </tr>
        </tbody>
      </table>
        '''

        subject_table = '''
          <table class="module-data">
            <thead>
              <tr>
                <th>Property</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>'''
        # Append the subject information
        pages[cert_num]['subject_data'] = {}
        for val in cert.subject.rdns:
          dn = val.rfc4514_string().split('=')
          pages[cert_num]['subject_data'][dn[0]] = dn[1]
          subject_table += f'''
            <tr>
              <td>{dn[0]}</td>
              <td>{dn[1]}</td>
            </tr>
          '''

        subject_table += '''
          </tbody>
        </table>'''

        # Append issuer information
        for val in cert.issuer.rdns:
          dn = val.rfc4514_string().split('=')
          if 'CN' in dn[0]:
            signed_by = dn[1]

        ext_table = ''

        # Append extensions information
        ext_data = []
        if cert.extensions:

          ext_table = '''
            <h5>Certificate Extensions</h5>
            <table class="module-data" style="margin-bottom:20px;">
              <thead>
                <tr>
                  <th>Property</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>'''
          pages[cert_num]['cert_ext'] = {}
          for extension in cert.extensions:
            if isinstance(extension.value, list):
              for extension_value in extension.value:
                pages[cert_num]['cert_ext'][extension.oid._name] = self.format_extension_value(extension_value.value)
                ext_table += f'''
                    <tr>
                      <td>{extension.oid._name}</td> 
                      <td>{self.format_extension_value(extension_value.value)}</td>
                    </tr> 
                  '''
            else:
              pages[cert_num]['cert_ext'][extension.oid._name] = self.format_extension_value(extension.value)
              ext_table += f'''
                    <tr>
                      <td>{extension.oid._name}</td>
                      <td>{self.format_extension_value(extension.value)}</td>
                    </tr> 
                  '''
          ext_table += '''
            </tbody>
          </table>'''

        # Add summary table row
        summary_table += f'''
              <tr>
                <td>{not_after}</td>
                <td>{cert_length}</td>
                <td>{public_key_type}</td>
                <td>{port}</td>
                <td>{signed_by}</td>
              </tr>
            </tbody>
          </table>
        '''
        pages[cert_num]['sammary_data'] = [not_after, cert_length, public_key_type, port, signed_by]

        # Merge all table HTML
        summary_table = f'\n{summary_table}'

        summary_table += f'''
        <div id="paired" style="display:flex;justify-content:space-between;">
          <div style="margin-right:20px;">
            <h5>Certificate Information</h5>
            {cert_table}
          </div>
          <div>
            <h5>Subject Information</h5>
            {subject_table}
          </div>
        </div>'''

        if ext_table is not None:
          summary_table += f'\n\n{ext_table}'


      outbound_conns = self._tls_util.get_all_outbound_connections(
          device_mac=self._device_mac, capture_files=pcap_files)
      conn_table = self.generate_outbound_connection_table(outbound_conns)

      html_content += summary_table + '\n'.join('\n' + tables
                                                for tables in cert_tables)
      html_content += conn_table

    else:
      html_content += ('''
        <div class="callout-container info">
          <div class="icon"></div>
          No TLS certificates found on the device
        </div>''')

    report_jinja = HTML
    for num,page in pages.items():
      module_header_repr = module_header if num == 0 else None
      page_html = template.render(
                                base_template=self._base_template_file,
                                module_header=module_header_repr,
                                summary_headers=summary_headers,
                                summary_data=page['sammary_data'],
                                cert_info_data=page['cert_info_data'],
                                subject_data=page['subject_data'],
                                cert_table_headers=cert_table_headers,
                                cert_ext=page['cert_ext'],
                                ountbound_headers=outbound_headers,
                              )
      report_jinja += page_html
      if outbound_conns:
        out_page = template.render(
                          base_template=self._base_template_file,
                          ountbound_headers=outbound_headers,
                          outbound_conns=outbound_conns
                        )
        report_jinja += out_page
    report_jinja += '</body></html>'


    LOGGER.debug('Module report:\n' + html_content)

    # Use os.path.join to create the complete file path
    report_path = os.path.join(self._results_dir, MODULE_REPORT_FILE_NAME)
    jinja_path = os.path.join(self._results_dir, 'example.html')

    # Write the content to a file
    with open(report_path, 'w', encoding='utf-8') as file:
      file.write(html_content)

    # Write the content to a file
    with open(jinja_path, 'w', encoding='utf-8') as file:
      file.write(report_jinja)

    LOGGER.info('Module report generated at: ' + str(report_path))
    return report_path

  def format_extension_value(self, value):
    if isinstance(value, bytes):
      # Convert byte sequences to hex strings
      return hexlify(value).decode()
    elif isinstance(value, (list, tuple)):
      # Format lists/tuples for HTML output
      return ', '.join([self.format_extension_value(v) for v in value])
    elif isinstance(value, ExtendedKeyUsage):
      # Handle ExtendedKeyUsage extension
      return ', '.join(
          [oid._name or f'Unknown OID ({oid.dotted_string})' for oid in value])
    elif isinstance(value, GeneralNames):
      # Handle GeneralNames (used in SubjectAlternativeName)
      return ', '.join(
          [name.value for name in value if isinstance(name, DNSName)])
    elif isinstance(value, SubjectAlternativeName):
      # Extract and format the GeneralNames (which contains DNSName,
      #IPAddress, etc.)
      return self.format_extension_value(value.get_values_for_type(DNSName))

    elif isinstance(value, ObjectIdentifier):
      # Handle ObjectIdentifier directly
      return value._name or f'Unknown OID ({value.dotted_string})'
    elif hasattr(value, '_name'):
      # Extract the name for OIDs (Object Identifiers)
      return value._name
    elif isinstance(value, AuthorityKeyIdentifier):
      # Handle AuthorityKeyIdentifier extension
      key_id = self.format_extension_value(value.key_identifier)
      cert_issuer = value.authority_cert_issuer
      cert_serial = value.authority_cert_serial_number

      return (f'key_identifier={key_id}, '
              f'authority_cert_issuer={cert_issuer}, '
              f'authority_cert_serial_number={cert_serial}')
    elif isinstance(value, SubjectKeyIdentifier):
      # Handle SubjectKeyIdentifier extension
      return f'digest={self.format_extension_value(value.digest)}'
    elif isinstance(value, BasicConstraints):
      # Handle BasicConstraints extension
      return f'ca={value.ca}, path_length={value.path_length}'
    elif isinstance(value, KeyUsage):
      # Handle KeyUsage extension
      return (f'digital_signature={value.digital_signature}, '
              f'key_cert_sign={value.key_cert_sign}, '
              f'key_encipherment={value.key_encipherment}, '
              f'crl_sign={value.crl_sign}')
    return str(value)  # Fallback to string conversion

  def generate_outbound_connection_table(self, outbound_conns):
    """Generate just an HTML table from a list of IPs"""
    html_content = '''
    <h1>Outbound Connections</h1>
    <table class="module-data">
      <thead>
          <tr>
              <th>Destination IP</th>
              <th>Port</th>
          </tr>
      </thead>
    <tbody>
    '''

    rows = [
        f'\t<tr><td>{ip}</td><td>{port}</td></tr>'
        for ip, port in outbound_conns
    ]
    html_content += '\n'.join(rows)

    # Close the table
    html_content += """
    </tbody>
    \r</table>
    """

    return html_content

  def extract_certificates_from_pcap(self, pcap_files, mac_address):
    # Initialize a list to store packets
    all_packets = []
    # Iterate over each file
    for pcap_file in pcap_files:
      # Open the capture file
      packets = pyshark.FileCapture(pcap_file)
      try:
        # Iterate over each packet in the file and add it to the list
        for packet in packets:
          all_packets.append(packet)
      finally:
        # Close the capture file
        packets.close()

    certificates = {}
    # Loop through each item (packet)
    for packet in all_packets:
      if 'TLS' in packet:
        # Check if the packet's source matches the target MAC address
        if 'eth' in packet and (packet.eth.src == mac_address):
          # Look for attribute of x509
          if hasattr(packet['TLS'], 'x509sat_utf8string'):
            certificate_bytes = bytes.fromhex(
                packet['TLS'].handshake_certificate.replace(':', ''))
            # Parse the certificate bytes
            certificate = x509.load_der_x509_certificate(
                certificate_bytes, default_backend())
            # Extract IP address and port from packet
            ip_address = packet.ip.src
            port = packet.tcp.srcport if 'tcp' in packet else packet.udp.srcport
            # Store certificate in dictionary with IP address and port as key
            certificates[(ip_address, port)] = certificate
    sorted_keys = sorted(certificates.keys(), key=lambda x: (x[0], x[1]))
    sorted_certificates = {k: certificates[k] for k in sorted_keys}
    return sorted_certificates

  def _security_tls_v1_2_server(self):
    LOGGER.info('Running security.tls.v1_2_server')
    self._resolve_device_ip()
    # If the ipv4 address wasn't resolved yet, try again
    if self._device_ipv4_addr is not None:
      tls_1_2_results = self._tls_util.validate_tls_server(
          self._device_ipv4_addr, tls_version='1.2')
      tls_1_3_results = self._tls_util.validate_tls_server(
          self._device_ipv4_addr, tls_version='1.3')
      results = self._tls_util.process_tls_server_results(
          tls_1_2_results, tls_1_3_results)
      # Determine results and return proper messaging and details
      description = ''
      result = results[0]
      details = results[1]
      if result is None:
        result = 'Feature Not Detected'
        description = 'TLS 1.2 certificate could not be validated'
      elif result:
        description = 'TLS 1.2 certificate is valid'
      else:
        description = 'TLS 1.2 certificate is invalid'
      return result, description, details

    else:
      LOGGER.error('Could not resolve device IP address. Skipping')
      return 'Error', 'Could not resolve device IP address'

  def _security_tls_v1_3_server(self):
    LOGGER.info('Running security.tls.v1_3_server')
    self._resolve_device_ip()
    # If the ipv4 address wasn't resolved yet, try again
    if self._device_ipv4_addr is not None:
      results = self._tls_util.validate_tls_server(self._device_ipv4_addr,
                                                   tls_version='1.3')
      # Determine results and return proper messaging and details
      description = ''
      result = results[0]
      details = results[1]
      description = ''
      if result is None:
        result = 'Feature Not Detected'
        description = 'TLS 1.3 certificate could not be validated'
      elif results[0]:
        description = 'TLS 1.3 certificate is valid'
      else:
        description = 'TLS 1.3 certificate is invalid'
      return result, description, details

    else:
      LOGGER.error('Could not resolve device IP address')
      return 'Error', 'Could not resolve device IP address'

  def _security_tls_v1_0_client(self):
    LOGGER.info('Running security.tls.v1_0_client')
    self._resolve_device_ip()
    # If the ipv4 address wasn't resolved yet, try again
    if self._device_ipv4_addr is not None:
      tls_1_0_valid = self._validate_tls_client(self._device_ipv4_addr, '1.0')
      tls_1_1_valid = self._validate_tls_client(self._device_ipv4_addr, '1.1')
      tls_1_2_valid = self._validate_tls_client(self._device_ipv4_addr, '1.2')
      tls_1_3_valid = self._validate_tls_client(self._device_ipv4_addr, '1.3')
      states = [
          tls_1_0_valid[0], tls_1_1_valid[0], tls_1_2_valid[0], tls_1_3_valid[0]
      ]
      if any(state is True for state in states):
        # If any state is True, return True
        result_state = True
        result_message = 'TLS 1.0 or higher detected'
      elif all(state == 'Feature Not Detected' for state in states):
        # If all states are "Feature not Detected"
        result_state = 'Feature Not Detected'
        result_message = tls_1_0_valid[1]
      elif all(state == 'Error' for state in states):
        # If all states are "Error"
        result_state = 'Error'
        result_message = ''
      else:
        result_state = False
        result_message = 'TLS 1.0 or higher was not detected'
      result_details = tls_1_0_valid[2] + tls_1_1_valid[2] + tls_1_2_valid[
          2] + tls_1_3_valid[2]
      result_tags = list(
          set(tls_1_0_valid[3] + tls_1_1_valid[3] + tls_1_2_valid[3] +
              tls_1_3_valid[3]))
      return result_state, result_message, result_details, result_tags
    else:
      LOGGER.error('Could not resolve device IP address. Skipping')
      return 'Error', 'Could not resolve device IP address'

  def _security_tls_v1_2_client(self):
    LOGGER.info('Running security.tls.v1_2_client')
    self._resolve_device_ip()
    # If the ipv4 address wasn't resolved yet, try again
    if self._device_ipv4_addr is not None:
      return self._validate_tls_client(self._device_ipv4_addr,
                                       '1.2',
                                       unsupported_versions=['1.0', '1.1'])
    else:
      LOGGER.error('Could not resolve device IP address. Skipping')
      return 'Error', 'Could not resolve device IP address'

  def _security_tls_v1_3_client(self):
    LOGGER.info('Running security.tls.v1_3_client')
    self._resolve_device_ip()
    # If the ipv4 address wasn't resolved yet, try again
    if self._device_ipv4_addr is not None:
      return self._validate_tls_client(self._device_ipv4_addr,
                                       '1.3',
                                       unsupported_versions=['1.0', '1.1'])
    else:
      LOGGER.error('Could not resolve device IP address. Skipping')
      return 'Error', 'Could not resolve device IP address'

  def _validate_tls_client(self,
                           client_ip,
                           tls_version,
                           unsupported_versions=None):
    client_results = self._tls_util.validate_tls_client(
        client_ip=client_ip,
        tls_version=tls_version,
        capture_files=[
            MONITOR_CAPTURE_FILE, STARTUP_CAPTURE_FILE, TLS_CAPTURE_FILE
        ],
        unsupported_versions=unsupported_versions)

    # Generate results based on the state
    result_state = None
    result_message = ''
    result_details = ''
    result_tags = []

    if client_results[0] is not None:
      result_details = client_results[1]
      if client_results[0]:
        result_state = True
        result_message = f'TLS {tls_version} client connections valid'
      else:
        result_state = False
        result_message = f'TLS {tls_version} client connections invalid'
    else:
      result_state = 'Feature Not Detected'
      result_message = 'No outbound connections were found'
    return result_state, result_message, result_details, result_tags

  def _resolve_device_ip(self):
    # If the ipv4 address wasn't resolved yet, try again
    if self._device_ipv4_addr is None:
      self._device_ipv4_addr = self._get_device_ipv4()
