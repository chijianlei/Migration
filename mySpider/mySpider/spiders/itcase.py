# -*- coding: utf-8 -*-
import scrapy


class ItcaseSpider(scrapy.Spider):
    name = 'itcast'
    allowed_domains = ['pytorch.org']
    start_urls = ['https://pytorch.org/docs/stable/index.html']

    def parse(self, response):
        # filename = "pytorch.html"
        # open(filename, 'wb+').write(response.body)
        filename = 'class.txt'
        wr = open(filename, 'w')

        context = response.xpath('//*[@id="pytorch-left-menu"]/div/div/ul[3]')
        for each in context:
            # line = each.extract()
            items = each.xpath('//*[@id="pytorch-left-menu"]/div/div/ul[3]/li[*]/a/@href').extract()
            for item in items:
                wr.write('https://pytorch.org/docs/stable/'+item+'\n')
                print('test:' + item)
        pass