

class EllipticCurve:

    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p

    def __str__(self):
        return f"y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})"


class Point:

    def __init__(self, x: int, y: int, curve: EllipticCurve):
        self.x = x
        self.y = y
        self.curve = curve

    def __str__(self):
        return f"({self.x}, {self.y})"

    def to_bytes(self):
        x_bytes = self.x.to_bytes((self.curve.p.bit_length() + 7) // 8, 'big')
        y_bytes = self.y.to_bytes((self.curve.p.bit_length() + 7) // 8, 'big')
        return x_bytes + y_bytes

    def add(self, other):
        if self.curve != other.curve:
            raise ValueError("Points do not belong to the same curve")

        if self == other:
            return self.double()

        if self.x is None:
            return other

        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return None

        p = self.curve.p
        a = self.curve.a

        m = (other.y - self.y) * pow(other.x - self.x, -1, p) % p
        x3 = (m * m - self.x - other.x) % p
        y3 = (m * (self.x - x3) - self.y) % p

        return Point(x3, y3, self.curve)

    def double(self):
        if self.x is None:
            return self

        p = self.curve.p
        a = self.curve.a

        m = (3 * self.x * self.x + a) * pow(2 * self.y, -1, p) % p
        x3 = (m * m - self.x - self.x) % p
        y3 = (m * (self.x - x3) - self.y) % p

        return Point(x3, y3, self.curve)

    def multiply(self, n: int):
        result = self
        addend = self

        while n:
            if n & 1:
                result = result.add(addend)
            addend = addend.double()
            n >>= 1

        return result
