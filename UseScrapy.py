# -*- coding:utf-8 -*-
'''
Created on 2018年4月2日

@author: Yu Qu
'''
import scrapy
from scrapy.selector import Selector

class Spider(scrapy.Spider):
    name="Pytorch"
    allowed_domains=["pytorch.org"]
    start_urls = [
        'https://pytorch.org/docs/stable/index.html',
    ]
    
    global write_file
    write_file=open('cryptocurrency-20181103.csv','w')
    write_file.write('Name,Short Name,CoinMarketURL,GitHubURL\n')
    
    global coin_dict
    coin_dict={}
    
    def parse(self,response):
        
#         write_file=open('cryptocurrency.csv','a')
        
        if('currencies' in response.url and not ('volume' in response.url)):
            for each in response.xpath('//meta[@property="og:title"]'):
                line=each.extract()
                content=line[line.index('content="')+9:line.rindex(') ')]
                print content
                coin_name=content.split(' (')[0]
                short_name=content.split(' (')[1]
                print coin_name
                print short_name
                coin_name=coin_name+':'+short_name
                
                
                
            for each in response.xpath('//li/a[starts-with(@href,"https://github.com/")]/@href'):
                github_url=each.extract()
                print github_url
#                 write_file.write(each.extract()+'\n')
            if(not coin_dict.has_key(coin_name)):
                coin_dict[coin_name]=short_name+','+response.url+','+github_url
                write_file.write(coin_name+','+short_name+','+response.url+','+github_url+'\n')
            
        
        for each in response.xpath('//a/@href'):
            suburl=each.extract()
            if(suburl.startswith('/currencies/')):
#                 print suburl
                yield scrapy.Request('https://coinmarketcap.com'+suburl, self.parse)
        
        
#         sel=Selector(response)
#         all_urls = sel.xpath('//a/@href')
#         for url in all_urls:
#             print url