import unittest

def create_test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests', pattern='test_*.py')
    return test_suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(create_test_suite())