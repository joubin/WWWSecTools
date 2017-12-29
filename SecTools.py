#!/usr/bin/env python
"""
Determine whether a website supports HSTS.
"""
from typing import Tuple, Any, List, Dict
import socket, ssl, requests, sys, csv
from enum import Enum

from nassl.ssl_client import OpenSslVersionEnum

http = "http://"
https = "https://"


class Value(Enum):
    NO = False
    NA = "Not Applicable"
    YES = True


class Result:
    def __init__(self, result, response):
        self.result: bool = result
        self.response: requests.Response = None


class Domain:
    def __init__(self, url: str):
        self.url: str = Domain.removeSchema(url)
        self.ssltls_version: str = Value.NA
        self.has_http: bool = Value.NO
        self.http_response: requests.Response = None
        self.has_https: bool = Value.NO
        self.https_response: requests.Response = None
        self.hsts: Value = Value.NA
        self.https_redirect = Value.NO

    def run(self):
        # is port 80 open?
        port80 = self.__has_open_port(port=80)
        if port80:
            # check for redirect
            can_connect = self.__can_connect(schema=http)
            if can_connect[0]:
                self.has_http = Value.YES
                self.http_response = can_connect[1]
                self.https_redirect = self.__is_HTTPSRedirect(
                    response=self.http_response)

        port443 = self.__has_open_port(port=443)
        if port443:
            self.hsts = self.__has_hsts()
            # check hsts
            # check ssl versions
            # check tls version
            # check other tls stuff

    def __crypt_stuff(self):
        import sslyze.server_connectivity as sc
        con = sc.ServerConnectivityInfo(hostname=self.url)
        con.test_connectivity_to_server()
        con.get_preconfigured_ssl_connection(override_ssl_version=OpenSslVersionEnum.TLSV1)
        con.get_preconfigured_ssl_connection(override_ssl_version=OpenSslVersionEnum.SSLV2)


    def __has_hsts(self) -> bool:
        """
        Connect to target site and check its headers."
        """
        try:
            self.https_response = requests.get(https + self.url)
        except requests.exceptions.SSLError as error:
            print("An error that should never happen happened: %s" % (error,),
                  file=(sys.stderr))
            return False

        if 'strict-transport-security' in self.https_response.headers:
            return True

        return False

    def __has_open_port(self, port: int = 80) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((self.url, port))
        try:
            sock.close()
        except:
            pass
        del sock
        if result == 0:
            return True
        return False

    def __is_HTTPSRedirect(self, response: requests.Response = None) -> Tuple[
        bool, requests.Response]:
        """
        :param url: given this url, check to see if the page is redirecting
        to an
        https location with proper HTTP Code :return: a Tuple. First part of the
        tuple is a boolean if the site is returing the right code and
        redirecting
        to HTTPS and providing the correct location
        """
        locationHTTPS = str(response.headers['Location']).startswith("https://")
        code301 = response.status_code == 301
        return code301 == locationHTTPS

    def __can_connect(self, schema: str = http) -> Tuple[bool, Any]:
        """
        :param url: url to test
        :return: Tuple. Index 0 is the http and Index 1 is https
        """
        try:
            httpResponse = requests.get(schema + self.url)
        except requests.exceptions.ConnectionError:
            return False, None

        return True, httpResponse

    @staticmethod
    def removeSchema(url: str) -> str:
        clean_url = url
        if url.startswith(http) or url.startswith(https):
            clean_url = url.lower().replace(http, "").replace(https, "")
        clean_url = clean_url.strip()

        return clean_url


def run():
    inputFile = None
    outputFile = None

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
