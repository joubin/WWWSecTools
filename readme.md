# WWWSecTools

I wrote this tool to enable larger orgs audit their external surface. 

Objective:
  * Test if port 80 is open
  * Test if port 443 is open
  * Test available TLS version
  * Test if the domain is parked* 
  * Test if the domain provides HSTS
  * Test if the domain redirects to TLS

### Domain Parking
Note that the "Parking" test is heuristically. I am using markers from domains that are parked and have created a some tests. 
You will be able to trick this test into thinking that a domain is parked, however, the idea is that the we don't know if a domain is parked. 
