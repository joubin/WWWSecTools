from unittest import TestCase
from WWWSecTools import *



class TestAlexa(TestCase):
    def test_alexa_download(self):
        a = Alexa()
        all_top = a.get_top()
        self.assertRaises(Exception, len(all_top), 1000000)


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
