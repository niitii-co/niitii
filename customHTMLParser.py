from html.parser import HTMLParser

class CustomParser(HTMLParser):
    def __init__(self, target_tag):
        super().__init__()
        self.target_tag = target_tag
        self.found_tags = []

    def handle_starttag(self, tag, attrs):
        if tag == self.target_tag:
#            self.found_tags.append({'tag': tag, 'attrs': attrs})
            for attr, value in attrs:
                if attr == 'src':
                    self.found_tags.append(value)

