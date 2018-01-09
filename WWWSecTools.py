import csv
import random
import socket
import string
import sys
import tempfile
from typing import List
from typing import Tuple, Any, Union
import dns.resolver
import os
import requests
import time
import tldextract
from bs4 import BeautifulSoup
from nassl._nassl import OpenSSLError
from nassl.ssl_client import OpenSslVersionEnum
from sslyze.utils.ssl_connection import SSLHandshakeRejected
from multiprocessing import Queue
import threading
import whois

HTTP = "http://"
HTTPS = "https://"
LOG = sys.stdout


# DEVNULL = open(os.devnull, 'w')
# LOG = DEVNULL


class Alexa:
    @staticmethod
    def get_top(top_n: int = 1000000) -> List[str]:
        file_name = "top1m.csv"
        ALEXA_DATA_URL = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'
        import zipfile, io
        r = WebDriver.request(url=ALEXA_DATA_URL)
        z = zipfile.ZipFile(io.BytesIO(r.content))
        folder = os.path.join(tempfile.gettempdir(), "csv")
        z.extractall(path=folder)
        file = os.path.join(folder, "top-1m.csv")
        with open(file, 'r') as alexa:
            alexa_csv = csv.reader(alexa, delimiter=',')
            return [line[1] for line in alexa_csv][:top_n]


class CSVWriter:
    def __init__(self, writer, header: List):
        self.writer = writer
        self.write_row(header)

    def write_row(self, row: List = None) -> None:
        if row is not None:
            if self.writer is not None:
                self.writer.writerow(row)
            else:
                print(row, file=LOG)

class WebDriver:
    WEB_DRIVER = requests.Session()
    WEB_DRIVER.headers.update({
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/63.0.3239.84 Safari/537.36'})
    @staticmethod
    def request(url : str = None, timeout:int = 60):
        return WebDriver.WEB_DRIVER.get(url=url, timeout=timeout)

class ParkedDomain(WebDriver):
    resolver = dns.resolver.Resolver()  # create a new instance named

    PARK_SERVICE = [
       "AstoriaCompany.com",
       "1plus.net",
       "Above.com",
       "ActiveAudience.com",
       "Bodis.com",
       "DDC.com",
       "DomainAdvertising.com",
       "DomainApps.com",
       "DomainSpa.com",
       "DomainSponsor.com",
       "Fabulous.com",
       "ParkLogic.com",
       "ParkQuick.com",
       "ParkingCrew.com",
       "RookMedia.net",
       "Skenzo.com",
       "SmartName",
       "TheParkingPlace.com",
       "TrafficZ.com",
       "Voodoo.com",
       "activeaudience.com",
       "afternic",
       "buydomains.com",
       "cybersync.com",
       "domainHop",
       "domainSpa",
       "domainSponsor",
       "domaindirect.com",
       "domainguru.com",
       "domainhop.com",
       "domaininformer.com",
       "domainrightnow.com",
       "domainsystems.com",
       "dotzup.com",
       "fabulous.com",
       "futurequest.net",
       "godaddy.com",
       "goldkey.com",
       "hostindex.com",
       "hugedomains.com",
       "iMonetize.com",
       "namedrive.com",
       "netvisibility.com",
       "oversee.net",
       "parked.com",
       "parkednames.com",
       "parking4income",
       "parkingcrew.com",
       "parkingdots",
       "parkingdots.com",
       "parkingsite",
       "parkingsite.com",
       "parkitnow",
       "parkitnow.com",
       "parkpage.com",
       "parkquick",
       "parkquick.com",
       "premiumtraffic.com",
       "revenuedirect",
       "searchportalinformation.com",
       "sedo.com",
       "sedoparking.com",
       "sedopro.com",
       "siteparker.com",
       "skenzo",
       "skenzo.com",
       "smartname.com",
       "snapnames.com",
       "streamic.com",
       "tafficvalet.com",
       "trafficclub.com",
       "trafficparking.com",
       "trafficz",
       "uniregistry.com",
       "webcom.com",
       "whypark.com"
                    ]

    def __init__(self, url, schema=HTTP):
        self.url = url
        self.schema = schema
        self.soup = self.__get_page()

    def __get_page(self):
        try:
            response = self.request(url=self.schema + self.url)
            content = response.content
            return BeautifulSoup(content, 'html.parser')
        except (
        requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            return None

    def has_parking_service_resources(self) -> bool:
        resources = [self.find_list_resources("script", "src"),
                     self.find_list_resources("img", "src"),
                     self.find_list_resources("iframe", "src")]
        clean = []
        for resource in resources:
            for each_item in resource:
                clean.append(ParkedDomain.get_domain(each_item))
        remove_self = ParkedDomain.PARK_SERVICE
        try:
            remove_self.remove(self.url)
        except ValueError:
            pass
        something = list(set(clean) & set(remove_self))
        return len(something) > 0

    def domain_has_random_subdomains(self) -> bool:
        subdomain = ''.join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(10))
        url = HTTP + subdomain + '.' + self.url

        try:
            response = self.request(url=url)
        except requests.exceptions.ConnectionError:
            return False
        if 'Location' in response.headers:
            if str(response.headers['Location']) == '':
                return True
        return False

    def __get_dns(self):
        try:
            result = ParkedDomain.resolver.query(self.url, "A")
        except:
            return []
        return [rdata for rdata in result]

    def __has_dns(self):
        return len(self.__get_dns()) > 0

    def __no_dns_record(self):
        return len(self.__get_dns()) == 0

    def __has_who_is(self):
        return whois.whois(url=self.url).status is not None

    def is_parked(self):
        has_parking_service_resource = self.has_parking_service_resources()
        domain_has_random_subdomains = self.domain_has_random_subdomains()
        has_who_is = self.__has_who_is()
        no_dns_record = self.__no_dns_record()
        return has_parking_service_resource or \
               domain_has_random_subdomains or \
               (has_who_is and no_dns_record)

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


class Domain(WebDriver):
    csv_format = ['URL', 'HTTP', 'HTTPS', 'Parked', 'HSTS', 'HTTPS Redirect',
                  'SSLV23',
                  'SSLV2', 'SSLV3', 'TLSV1', 'TLSV1_1', 'TLSV1_2', 'TLSV1_3']


    def __init__(self, url: str, csv_writer: CSVWriter = None):
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

    def run(self, a_queue: Queue):
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
        try:
            print("Put data on the queue", file=LOG)
            a_queue.put(self.make_data())
        except:
            print("Couldnt put data on the queue", file=sys.stderr)

        print("%s" % self.make_data(), file=LOG)

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
            self.https_response = self.request(HTTPS + self.url)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.SSLError) as error:
            print("An error for %s when checking HSTS. \nError: %s" % (
                self.url, error,),
                  file=sys.stderr)
            self.hsts = False

        if 'strict-transport-security' in self.https_response.headers:
            self.hsts = True

        return self.hsts

    def has_open_port(self, port: int = 80, retry: int = 10) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try_count = retry
        result = None
        while try_count > 0 and result is None:
            try:
                result = sock.connect_ex((self.url, port))
            except Exception as error:
                print("error opening %s on port %s with error: %s" % (self.url, port, error), file=sys.stderr)
                try_count -= 1
                time.sleep(1)

        # noinspection PyBroadException
        try:
            sock.close()
        except:
            # We don't care if we don't close it!
            pass
        del sock
        if result is None:
            return False
        elif result == 0:
            return True
        else:
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
        except (AttributeError, KeyError):
            locationHTTPS = False
        code301 = response.status_code == 301
        return code301 == locationHTTPS

    def can_connect(self, schema: str = HTTP, timeout: int = 10) -> Tuple[
        bool, Any]:
        """
        :return: Tuple. Index 0 is the http and Index 1 is https
        """
        try:
            httpResponse = self.request(schema + self.url)
        except (
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout):
            return False, None

        return True, httpResponse

    def make_data(self) -> List[Union[str, bool]]:
        columns = [self.url, self.has_http, self.has_https, self.is_parked,
                   self.hsts,
                   self.https_redirect]
        for i in OpenSslVersionEnum:
            columns.append(self.ssl_version_support[i])

        return columns

    def write_to_csv(self):
        """
        :return: Nothing, purly operational task
        """
        data = self.make_data()
        self.csv_writer.write_row(data)

    @staticmethod
    def remove_schema(url: str) -> str:
        clean_url = url
        if url.startswith(HTTP) or url.startswith(HTTPS):
            clean_url = url.lower().replace(HTTP, "").replace(HTTPS, "")
        clean_url = clean_url.strip()

        return clean_url


def run(urls: List[str], csv_writer: CSVWriter, active_threads : int = 4) -> None:

    def __join_jobs(jobs : List[threading.Thread]) -> None:
        for job in jobs:
            print("Waiting on %s" % job.name, file=LOG)
            job.join()

    jobs: List[threading.Thread] = []
    thread_count = active_threads
    print_queue = Queue()
    for url in urls:
        print(url)
        domain = Domain(url=url)
        job = threading.Thread(target=domain.run, args=(print_queue,), name=url)
        jobs.append(job)
        job.start()
        thread_count -= 1
        if thread_count == 0:
            thread_count = active_threads
            __join_jobs(jobs)


    print("Started everything")
    __join_jobs()

    print("Everythong joined, will start writing")
    while not print_queue.empty():
        item = print_queue.get()
        print(item)
        csv_writer.write_row(item)


def input_to_list() -> List[str]:
    try:
        inputFile = str(sys.argv[1])
    except IndexError:
        print("Please include an input file and an out output file like so: " +
              sys.argv[0] + " inputFile.txt outputFile.csv", file=sys.stderr,
              flush=True)
        sys.exit(31)

    with open(inputFile, "r") as in_file:
        urls: List[str] = [line for line in in_file]
        return urls


def output_to_csvwriter() -> CSVWriter:
    try:
        outputFile = str(sys.argv[2])
    except IndexError:
        print("Please include an input file and an out output file like so: " +
              sys.argv[0] + " inputFile.txt outputFile.csv", file=sys.stderr,
              flush=True)
        sys.exit(31)
    out_file = open(outputFile, 'w')
    csv_writer = CSVWriter(
        writer=csv.writer(out_file, delimiter=','),
        header=Domain.csv_format)
    return csv_writer


def test_random_domains():
    from itertools import product
    from string import ascii_lowercase
    keywords = [''.join(i) for i in product(ascii_lowercase, repeat=5)]
    with open('output.csv', 'w') as out_file:
        csv_writer = CSVWriter(
            writer=csv.writer(None, delimiter=','),
            header=Domain.csv_format)
        for schema in ['.com', '.net']:
            for domain in keywords:
                url = domain + schema
                print(url)
                park = Domain(url=url, csv_writer=csv_writer)
                park.run()


if __name__ == '__main__':
    # run()
    # test()
    # test_random_domains()
    # urls = input_to_list()
    csv_writer = output_to_csvwriter()
    urls = Alexa().get_top(top_n=1000)
    #
    run(urls=urls, csv_writer=csv_writer)
    # q = queue.Queue()
    # d = Domain('apple.com')
    # d.run(queue=q)

    # d = Domain(url='microsoft.com')
    # q = Queue()
    # d.run(a_queue=q)
    # print(d.make_data())
