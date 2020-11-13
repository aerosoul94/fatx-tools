from ..signature import FatXSignature


class LiveSignature(FatXSignature):
    def test(self):
        if self.read(4) == 'LIVE':
            return True
        return False

    def parse(self):
        self.length = 0