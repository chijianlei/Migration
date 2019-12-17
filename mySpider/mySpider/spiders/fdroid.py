# -*- coding: utf-8 -*-
import scrapy


class FdroidSpider(scrapy.Spider):
    name = 'fdroid'
    allowed_domains = ['f-droid.org']
    start_urls = ['https://f-droid.org/en/packages/']

    def parse(self, response):
        # filename = "pytorch.html"
        # open(filename, 'wb+').write(response.body)

        context = response.xpath('//*[@id="full-package-list"]/a[*]/@href')
        for each in context:
            url = 'https://f-droid.org'
            url = url + str(each.extract()+'/')
            print('test:' + str(url))
            yield scrapy.Request(url, callback=self.parse_dir_content)

        next_page = response.xpath('//*[@id="full-package-list"]/ul/li[13]/a/@href').extract()

        if next_page:
            next_page = 'https://f-droid.org'+str(next_page)[2:str(next_page).__len__()-2]
            print('next_page:'+next_page)
            yield scrapy.Request(next_page, callback=self.parse)


    def parse_dir_content(self, response):
        filename = 'giturl.txt'
        wr = open(filename, 'a')
        context = response.xpath('/html/body/div/div/div[1]/article/ul/li[*]/a')
        for index, each in enumerate(context):
            text = each.xpath('text()').extract()
            url = str(each.xpath('@href').extract())
            url = url[2:url.__len__()-2]
            if 'Source Code' in text:
                print('url:'+url)
                wr.write(url+'\n')
        pass