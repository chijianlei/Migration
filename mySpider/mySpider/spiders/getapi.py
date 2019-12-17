# -*- coding: utf-8 -*-
import scrapy
import xml.etree.cElementTree as ET

class ItcaseSpider(scrapy.Spider):
    name = 'getapi'
    allowed_domains = ['pytorch.org']
    start_urls = ['https://pytorch.org/docs/stable/torch.html']

    def parse(self, response):
        # filename = "pytorch.html"
        # open(filename, 'wb+').write(response.body)
        lists = self.start_urls[0].split("/")
        pageName = lists[len(lists)-1].split(".")[0]
        print(pageName)
        filename = 'api_'+pageName+'.txt'
        wr = open(filename, 'w', encoding="utf-8")

        context = response.xpath('//*[@id="pytorch-article"]')
        for each in context:
            # line = each.extract()
            items = each.xpath('//div[@class="section"]/dl[@class="function"]/dt').extract()
            print(str(len(items)))
            # print(items[214])
            # root = ET.fromstring(items[213])
            # api = ""
            # for child in root:
            #     if str(child.tag) != "a":
            #         if str(child.tail) == "None":
            #             api = api+str(child.text)
            #         else:
            #             api = api + str(child.text)+str(child.tail)
            #         print(child.text, child.tail)
            # print(api)
            for item in items:
                root = ET.fromstring(item)
                api = ""
                for child in root:
                    if str(child.tag) != "a":
                        if str(child.tail) == "None":
                            api = api + str(child.text)
                        else:
                            api = api + str(child.text) + str(child.tail)
                        # print(child.text, child.tail)
                print(api)
                wr.write(api+"\n")

            # for item in items:


            count = 0
            # for item in items:
            #     # data = item.xpath('//dt[@id="torch.is_tensor"]').extract()
            #     # print(str(len(data)))
            #     print(item)
            #     count = count+1
        pass