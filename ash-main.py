import re 
import csv
import datetiime 
from dateutil.relativedelta import relativedelta
import fileinput
import pandas as pd

current = datetime.date.today()
three = relativedelta(months=3)
dplus = currentd + three
source = input('What\'s the IOC source file? Include extension')
pizza = open(source, newline='')
whear = input('where do you want this file to end up?')
action = input('what will you call the alert title when this alret triggers?')
severity = input('What is the severity level? Informational/Low/Medium/High') 
altitle = input('What will you call the alert title  when this alert triggers?') 
description = input('What is the description for these threat alerts?')
reqact = input('What will appear for a recommended action when this alert triggers?')
outputw = open(whear+str(currentd)+'-'+altitle+'duplicates'+'.csv','w+', encoding='utf-8',newline='')
outputnew = open(whear+str(currentd)+'-'+altitle+'.csv','w+', encoding='utf-8',newline='')

for line in pizza: 
	new_words = re.findall("[a-f0-9]{64}",line, re.M|re.I)
	print(new_words)
csv_writer = csv.writer(outputw)
#header
csv_writer.writerow(['IndicatorType','IndicatorValue','ExpirationTime','Action','Severity','Title','Description','RecommendationActions','RbacGroups'])

#for sha256
for word in new_words:
#	csv_writer.writerow(['FileSha256', word, ])
	csv_writer.writerow(['FileShare256',word,dplus,action,severity,altitle,description,reqact,' '])

reader = outputw
lines = reader.read().split("\n")
reader.close()
