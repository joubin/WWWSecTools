if __name__ == '__main__':
    from WWWSecTools import *
    dataset1 = ["pcyr.org", "payd.org", "frbchi.com", "jabbari.io", "godaddy.com", "frbny.com"]
    dataset2 = ["diply.com"]
    for i in dataset2:
        pd = ParkedDomain(url=i, schema=HTTP)
        print("is %s parked: %s" % (i,pd.is_parked()))

