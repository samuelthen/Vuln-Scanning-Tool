import csv
from io import StringIO
import logging
from pygtrie import CharTrie

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger('BinList')

class BinRecord:
    def __init__(self, bin, brand, category, issuer):
        self.bin = bin
        self.brand = brand
        self.category = category
        self.issuer = issuer

    def __repr__(self):
        return f'BinRecord(bin={self.bin}, brand={self.brand}, category={self.category}, issuer={self.issuer})'

class BinList:
    BINLIST_FILE = 'src/passive_scan/passive_scan_rules/utils/binlist-data.csv'
    _singleton = None

    def __init__(self):
        self.trie = self.create_trie()

    @classmethod
    def get_singleton(cls):
        if cls._singleton is None:
            cls._create_singleton()
        return cls._singleton

    @classmethod
    def _create_singleton(cls):
        if cls._singleton is None:
            cls._singleton = BinList()

    def create_trie(self):
        trie = CharTrie()
        try:
            with open(self.BINLIST_FILE, mode='r', encoding='utf-8-sig') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    bin = row['bin']
                    trie[bin] = BinRecord(bin, row['brand'], row['category'], row['issuer'])
        except FileNotFoundError as e:
            LOGGER.warning(f"File not found: {self.BINLIST_FILE}", exc_info=e)
        except Exception as e:
            LOGGER.warning(f"Exception while loading: {self.BINLIST_FILE}", exc_info=e)
        return trie

    def get(self, candidate):
        for length in [6, 8, 5, 7]:
            bin = candidate[:length]
            bin_rec = self.trie.get(bin)
            if bin_rec:
                return bin_rec
        return None