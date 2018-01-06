import csv
import multiprocessing
import queue
import socket
import sys
import time
from typing import Tuple, Any, List, Union
from typing import List

from bs4 import BeautifulSoup
import requests
import tldextract
import random
import string
import sched, time

from nassl._nassl import OpenSSLError
from nassl.ssl_client import OpenSslVersionEnum
from sslyze.utils.ssl_connection import SSLHandshakeRejected

HTTP = "http://"
HTTPS = "https://"
LOG = sys.stdout

ALL_FINISHED = False


# import os
# DEVNULL = open(os.devnull, 'w')
# LOG = DEVNULL

class CSVWriter:
    def __init__(self, writer, header: List):
        self.writer = writer
        self.queue = queue.Queue()
        self.write_row(header)


    def close(self):
        global ALL_FINISHED
        ALL_FINISHED = True

    def write_row(self, row: List = None) -> None:
        self.queue.put(row)

    def run(self):
        global ALL_FINISHED
        print("Running")
        while not ALL_FINISHED:
            print("waiting for something and is finished = %s " % ALL_FINISHED)

            try:
                row = self.queue.get(timeout=3)

            except queue.Empty:
                pass
            finally:
                if row is not None:
                    if self.writer is not None:
                        self.writer.writerow(row)
                    else:
                        print(row, file=LOG)
        print("CSV Writer Done")


class ParkedDomain:
    PARK_SERVICE = ["smartname.com", "sedo.com", "parkingcrew.com",
                    "uniregistry.com", "hugedomains.com"]

    def __init__(self, url, schema=HTTP):
        self.url = url
        self.schema = schema
        self.soup = self.__get_page()

    def __get_page(self):
        try:
            response = requests.get(url=self.schema + self.url,
                                    headers=Domain.HEADERS)
            content = response.content
            return BeautifulSoup(content, 'html.parser')
        except (requests.exceptions.ConnectionError):
            return None

    def has_parking_service_resources(self) -> bool:
        resources = [self.find_list_resources("script", "src"),
                     self.find_list_resources("img", "src")]
        clean = []
        for resource in resources:
            for each_item in resource:
                clean.append(ParkedDomain.get_domain(each_item))
        something = list(set(clean) & set(ParkedDomain.PARK_SERVICE))
        return len(something) > 0

    def domain_has_random_subdomains(self) -> bool:
        subdomain = ''.join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(10))
        url = HTTP + subdomain + '.' + self.url

        try:
            response = requests.get(url=url, headers=Domain.HEADERS, )
        except requests.exceptions.ConnectionError:
            return False
        if 'Location' in response.headers:
            if str(response.headers['Location']) == '':
                return True
        return False

    def is_parked(self):
        return self.has_parking_service_resources() or \
               self.domain_has_random_subdomains()

    @staticmethod
    def get_domain(url: str) -> str:
        extracted = tldextract.extract(url)
        return "{}.{}".format(extracted.domain, extracted.suffix)

    def find_list_resources(self, tag, attribute) -> List:
        list = []
        if self.soup is None:
            return []

        for x in self.soup.findAll(tag):
            try:
                list.append(x[attribute])
            except KeyError:
                pass
        return list


class Domain:
    csv_format = ['URL', 'HTTP', 'HTTPS', 'Parked', 'HSTS', 'HTTPS Redirect',
                  'SSLV23',
                  'SSLV2', 'SSLV3', 'TLSV1', 'TLSV1_1', 'TLSV1_2', 'TLSV1_3']

    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/63.0.3239.84 Safari/537.36'}

    def __init__(self, url: str, csv_writer: CSVWriter):
        self.url: str = Domain.remove_schema(url)
        self.has_http: bool = False
        self.http_response: requests.Response = None
        self.has_https: bool = False
        self.https_response: requests.Response = None
        self.hsts = False
        self.https_redirect = False
        self.is_parked = False
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
                self.is_parked = self.is_domain_parked(schema=HTTP)
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
                self.is_parked = self.is_domain_parked(schema=HTTPS)
            # check ssl versions
            # check tls version
            # check other tls stuff
        self.write_to_csv()
        print("Finished: %s" % self.url, file=LOG)

    def is_domain_parked(self, schema=HTTP) -> bool:
        pd = ParkedDomain(url=self.url, schema=schema)
        return pd.is_parked()

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
            self.https_response = requests.get(HTTPS + self.url,
                                               headers=Domain.HEADERS)
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
        try:
            result = sock.connect_ex((self.url, port))
        except socket.gaierror:
            return False
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

    def can_connect(self, schema: str = HTTP, timeout: int = 10) -> Tuple[
        bool, Any]:
        """
        :return: Tuple. Index 0 is the http and Index 1 is https
        """
        try:
            httpResponse = requests.get(schema + self.url, timeout=timeout,
                                        headers=Domain.HEADERS)
        except (
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout):
            return False, None

        return True, httpResponse

    def write_to_csv(self):
        """
        :return: Nothing, purly operational task
        """

        def __make_data() -> List[Union[str, bool]]:
            columns = [self.url, self.has_http, self.has_https, self.is_parked,
                       self.hsts,
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
    jobs: List[multiprocessing.Process] = []
    domains: List[Domain] = []
    csv_writer_process = None
    csv_writer = None
    start = time.time()

    with open(inputFile, "r") as in_file:
        with open(outputFile, 'w') as out_file:
            csv_writer = CSVWriter(
                writer=csv.writer(out_file, delimiter=','),
                header=Domain.csv_format)
            csv_writer_process = multiprocessing.Process(target=csv_writer.run,
                                                         name="writer")
            csv_writer_process.start()
            for line in in_file:
                url = line
                domain = Domain(url=url, csv_writer=csv_writer)
                domains.append(domain)
                job = multiprocessing.Process(target=domain.run, name=url)
                jobs.append(job)
                job.start()

    for job in jobs:
        print("waiting on %s" % job.name)
        job.join()
    print("All done")
    csv_writer.close()
    csv_writer_process.join()
    end = time.time()
    print("took %s seconds to run" % (end - start,))


def test():
    # site = "jabbari.io"
    # # noinspection PyTypeChecker
    # d = Domain(url=site, csv_writer=CSVWriter(writer=None, header=None))
    # print(Domain.csv_format)
    # d.run()
    from ParkDetection import ParkedDomain as PD
    p = PD()


def test_random_domains():
    from itertools import product
    from string import ascii_lowercase
    keywords = [''.join(i) for i in product(ascii_lowercase, repeat=5)]
    jobs: List[multiprocessing.Process] = []
    with open('output.csv', 'w') as out_file:
        csv_writer = CSVWriter(
            writer=csv.writer(None, delimiter=','),
            header=Domain.csv_format)
        for schema in ['.com', '.net']:
            for domain in keywords:
                url = domain + schema
                print(url)
                park = Domain(url=url, csv_writer=csv_writer)
                process = multiprocessing.Process(target=park.run)
                jobs.append(process)
                process.start()
        for i in jobs:
            i.join()


if __name__ == '__main__':
    run()
    # test()
    # test_random_domains()
