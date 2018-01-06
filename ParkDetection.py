


if __name__ == '__main__':
    import string
    from itertools import product
    from string import ascii_lowercase
    from WWWSecTools import *
    keywords = [''.join(i) for i in product(ascii_lowercase, repeat=5)]
    csvWriter = CSVWriter(writer=None, header=None)
    for schema in ['.com', '.net']:
        for domain in keywords:
            url = domain+schema
            print(url)
            park = Domain(url=url, csv_writer=csvWriter)
            park.run()
            if park.has_http:
                park.is_domain_parked()
            if park == True:
                _is = "is"
            else:
                _is = "isn't"
            print("%s %s parked" %(url, _is ))
