from unittest import TestCase
from WWWSecTools import *

#
# class TestAlexa(TestCase):
#     def test_alexa_download(self):
#         a = Alexa()
#         all_top = a.get_top()
#         self.assertRaises(Exception, len(all_top), 1000000)


class TestCSVWriter(TestCase):

    def test_csv_writer(self):
        """
            Tests that the csv writer is able to read and write the same content
        """
        file = os.path.join(tempfile.gettempdir())
        file = str(file) + "test.csv"

        print(file)

        with open(file, 'w') as filepointer:
            writer = csv.writer(filepointer)
            CSVWriter(writer=writer, header=Domain.csv_format)

        with open(file, 'r') as filepointer:
            self.assertEqual(filepointer.readline().strip(),
                             ','.join(Domain.csv_format))


class TestWebDriver(TestCase):

    def test_web_driver(self):
        """
        This tests that the content retrieved from the WebDriver, which aims
        to have a common interface for all requests, is the same of that as a
        generic driver

         :return:
        """
        EXAMPLE_DOMAIN = "http://example.com"
        content1: requests.Response = WebDriver.request(url=EXAMPLE_DOMAIN,
                                                        timeout=100).content
        content2: requests.Response = requests.get(url=EXAMPLE_DOMAIN,
                                                   timeout=100).content
        self.assertEqual(content1, content2)


class ParkingDomainTest(TestCase):

    def test_parking_true(self):
        pd = ParkedDomain(url="anysecnow.com")  # I've parked anysecnow.com
        parked = pd.is_parked()
        self.assertEqual(parked, True)

    def test_parking_false(self):
        pd = ParkedDomain(url="example.com")
        parked = pd.is_parked()
        self.assertEqual(parked, False)


class DomainTest(TestCase):
    def test_domain_run(self):
        domain = Domain(url='jabbari.io')
        domain.run()
        data = domain.make_data()
        truth = "jabbari.io,True,True,False,True,True,True,False,False,True,True,True,False"
        self.assertEqual(','.join(data), truth)