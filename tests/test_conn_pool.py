import unittest

from conn_pool import ConnectionPool


class Dummy:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class TestPool(unittest.TestCase):
    def test_reuse(self):
        created = []

        def factory():
            d = Dummy()
            created.append(d)
            return d

        pool = ConnectionPool(factory, max_idle=2, max_age_sec=60)
        a = pool.acquire()
        pool.release(a, reusable=True)
        b = pool.acquire()
        self.assertIs(a, b)
        self.assertEqual(pool.stats["reused"], 1)
        self.assertEqual(len(created), 1)

    def test_non_reusable_closed(self):
        pool = ConnectionPool(Dummy, max_idle=2)
        a = pool.acquire()
        pool.release(a, reusable=False)
        self.assertTrue(a.closed)
        self.assertEqual(pool.stats["idle"], 0)


if __name__ == "__main__":
    unittest.main()
