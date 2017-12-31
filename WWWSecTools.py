import csv
import requests
import socket
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple, Any, List, Union

from nassl._nassl import OpenSSLError
from nassl.ssl_client import OpenSslVersionEnum
from sslyze.utils.ssl_connection import SSLHandshakeRejected

HTTP = "http://"
HTTPS = "https://"
LOG = sys.stdout
# DEVNULL = open(os.devnull, 'w')
# LOG = DEVNULL

class CSVWriter:
    def __init__(self, writer, header: List):
        self.writer = writer
        self.write_row(header)

    def write_row(self, row: List = None) -> None:
        if self.writer is not None:
            self.writer.writerow(row)
        else:
            print(row, file=LOG)


class Domain:
    csv_format = ['URL', 'HTTP', 'HTTPS', 'HSTS', 'HTTPS Redirect', 'SSLV23',
                  'SSLV2', 'SSLV3', 'TLSV1', 'TLSV1_1', 'TLSV1_2', 'TLSV1_3']

    HEADERS = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36'}
    def __init__(self, url: str, csv_writer: CSVWriter):
        self.url: str = Domain.remove_schema(url)
        self.has_http: bool = False
        self.http_response: requests.Response = None
        self.has_https: bool = False
        self.https_response: requests.Response = None
        self.hsts = False
        self.https_redirect = False
        self.ssl_version_support = {}

        for item in OpenSslVersionEnum:
            self.ssl_version_support[item] = False

        self.csv_writer = csv_writer

    def run(self):
        # is port 80 open?
        print("\tTesting %s ---> Port 80" % (self.url,), file=LOG)
        port80 = self.has_open_port(port=80)
        if port80:
            # check for redirect
            print("\tTesting %s ---> can connect http" % (self.url,), file=LOG)
            can_connect = self.can_connect(schema=HTTP)
            if can_connect[0]:

                self.has_http = True
                self.http_response = can_connect[1]
                print("\tTesting %s ---> redirect" % (self.url,), file=LOG)
                self.https_redirect = self.is_https_redirect(
                    response=self.http_response)
        print("\tTesting %s ---> Port 443" % (self.url,), file=LOG)
        port443 = self.has_open_port(port=443)
        if port443:
            print("\tTesting %s ---> can connect https" % (self.url,), file=LOG)
            can_connect = self.can_connect(schema=HTTPS)
            if can_connect[0]:
                self.has_https = True
                print("\tTesting %s ---> has hsts" % (self.url,), file=LOG)
                self.hsts = self.has_hsts()
                print("\tTesting %s ---> crypto" % (self.url,), file=LOG)
                self.crypt_stuff()
            # check ssl versions
            # check tls version
            # check other tls stuff
        print("Finished: %s" % (self.url))
        self.write_to_csv()

    def is_domain_parked(self) -> bool:
        raise NotImplementedError
        # pull the page and check for *park*.css and *park*.js
        # pull / and /+random data, if pages match, its probably parked
        # each visit to / resutls in a different url being tacked on
        # redirects to a site one of these sites
        ["https://uniregistry.com"]


    def crypt_stuff(self):
        import sslyze.server_connectivity as sc
        con = sc.ServerConnectivityInfo(hostname=self.url)

        for ssl_tls_versions in OpenSslVersionEnum:
            con2 = con.get_preconfigured_ssl_connection(ssl_tls_versions)
            try:
                con2.connect()
                self.ssl_version_support[ssl_tls_versions] = True
            except (SSLHandshakeRejected, OpenSSLError):
                self.ssl_version_support[ssl_tls_versions] = False

    def has_hsts(self) -> bool:
        """
        Connect to target site and check its headers."
        """
        try:
            self.https_response = requests.get(HTTPS + self.url, headers=Domain.HEADERS)
        except requests.exceptions.SSLError as error:
            print("An error for %s when checking HSTS. \nError: %s" % (
                self.url, error,),
                  file=sys.stderr)
            self.hsts = False

        if 'strict-transport-security' in self.https_response.headers:
            self.hsts = True

        return self.hsts

    def has_open_port(self, port: int = 80) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((self.url, port))
        # noinspection PyBroadException
        try:
            sock.close()
        except:
            # We don't care if we don't close it!
            pass
        del sock
        if result == 0:
            return True
        return False

    @staticmethod
    def is_https_redirect(response: requests.Response = None) \
            -> Tuple[bool, requests.Response]:
        """
        :param response:
        to an
        https location with proper HTTP Code :return: a Tuple. First part of the
        tuple is a boolean if the site is returing the right code and
        redirecting
        to HTTPS and providing the correct location
        """
        try:
            locationHTTPS = str(response.headers['Location']).startswith(
                "https://")
        except KeyError:
            locationHTTPS = False
        code301 = response.status_code == 301
        return code301 == locationHTTPS

    def can_connect(self, schema: str = HTTP, timeout:int = 10) -> Tuple[bool, Any]:
        """
        :return: Tuple. Index 0 is the http and Index 1 is https
        """
        try:
            httpResponse = requests.get(schema + self.url, timeout=timeout, headers=Domain.HEADERS)
        except requests.exceptions.ConnectionError:
            return False, None

        return True, httpResponse

    def write_to_csv(self):
        """
        :return: Nothing, purly operational task
        """

        def __make_data() -> List[Union[str, bool]]:
            columns = [self.url, self.has_http, self.has_https, self.hsts,
                       self.https_redirect]
            for i in OpenSslVersionEnum:
                columns.append(self.ssl_version_support[i])

            return columns

        data = __make_data()
        self.csv_writer.write_row(data)

    @staticmethod
    def remove_schema(url: str) -> str:
        clean_url = url
        if url.startswith(HTTP) or url.startswith(HTTPS):
            clean_url = url.lower().replace(HTTP, "").replace(HTTPS, "")
        clean_url = clean_url.strip()

        return clean_url


def run():
    try:
        inputFile = str(sys.argv[1])
    except IndexError:
        print("Please include an input file and an out output file like so: " +
              sys.argv[0] + " inputFile.txt outputFile.csv", file=sys.stderr,
              flush=True)
        sys.exit(31)

    try:
        outputFile = str(sys.argv[2])
    except IndexError:
        print("Please include an input file and an out output file like so: " +
              sys.argv[0] + " inputFile.txt outputFile.csv", file=sys.stderr,
              flush=True)
        sys.exit(31)

    start = time.time()
    with open(inputFile, "r") as in_file:
        with open(outputFile, 'w') as out_file:
            with ThreadPoolExecutor(max_workers=10) as executor:
                csv_writer = CSVWriter(
                    writer=csv.writer(out_file, delimiter=','),
                    header=Domain.csv_format)
                for line in in_file:
                    url = line
                    domain = Domain(url=url, csv_writer=csv_writer)
                    executor.submit(fn=domain.run)

    end = time.time()
    print("took %s seconds to run" %(end-start,))


def test():
    # site = "jabbari.io"
    # # noinspection PyTypeChecker
    # d = Domain(url=site, csv_writer=CSVWriter(writer=None, header=None))
    # print(Domain.csv_format)
    # d.run()
    from ParkDetection import ParkedDomain as PD
    p = PD()

if __name__ == '__main__':
    # run()
    test()
