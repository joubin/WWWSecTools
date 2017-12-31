from typing import List
import itertools

from bs4 import BeautifulSoup
import requests
import tldextract
import random
import string
from WWWSecTools import Domain
from WWWSecTools import HTTP, HTTPS


class ParkedDomain:
    PARK_SERVICE = ["smartname.com", "sedo.com", "parkingcrew.com"]

    def __init__(self, url):
        self.url = url
        self.soup = self.__get_page()

    def __get_page(self):
        response = requests.get(url=HTTP+self.url, headers=Domain.HEADERS)
        content = response.content
        return BeautifulSoup(content, 'html.parser')

    def has_parking_service_resources(self):
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
        url = HTTP+subdomain+'.'+self.url
        print(url)
        response = requests.get(url=url, headers=Domain.HEADERS)
        if 'Location' in response.headers:
            if str(response.headers['Location']) == '':
                return True
        return False

    def is_parked(self):
        return self.has_parking_service_resources() or self.domain_has_random_subdomains()



    @staticmethod
    def get_domain(url: str) -> str:
        extracted = tldextract.extract(url)
        return "{}.{}".format(extracted.domain, extracted.suffix)

    def find_list_resources(self, tag, attribute) -> List:
        list = []
        for x in self.soup.findAll(tag):
            try:
                list.append(x[attribute])
            except KeyError:
                pass
        return list


if __name__ == '__main__':
    p = ParkedDomain(url="ww8.home.com")
    print(p.is_parked())
