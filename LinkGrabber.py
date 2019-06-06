import mechanize
import requests as r
import re
import json
from bs4 import BeautifulSoup as b
br=mechanize.Browser()

br.set_handle_robots(False)

URL="https://sitecheck.sucuri.net/"         # site to check externel link is malicious or not 

br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]

response=br.open("https://abc.com/")  #enter the your site to check the extenel links 

list_of_links=[]

scrabed_links=[]

for link in br.links():

	#print(link.url)

	list_of_links.append(link.url)

print("list of all url lists:\n")
for j in list_of_links:

	print(j)

for i in list_of_links:

   link1=re.match('https?:\/\/(www)?',i)         #regex to grab the full link and check with sitecheck
   
   if(link1):

   	scrabed_links.append(i)
print("eternel links of the given site:")
print(scrabed_links)
length=len(scrabed_links)
count=0
print("suspicious check of the externel links:")
while count<length:
  j=scrabed_links[count]
  
  PARAMS={'scan':j}
  data=r.get(url=URL,params=PARAMS)

  data2=data.text
  
  data3=re.search('Domain\s{0,10}blacklisted\s{0,10}by\s{0,10}\w{1,50}',data2)#find the site is blacklisted or not 
  if(data3):
  	print("the domain {} is suspicious".format(j))
  else:
  	print("domain {} is not suspicious".format(j))

  count=count+1
