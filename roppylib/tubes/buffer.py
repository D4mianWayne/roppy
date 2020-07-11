#!/usr/bin/env python3


class Buffer(Exception):
    """
    List of bytes with some helper routines.

    Example:

        >>> b = Buffer()
        >>> b.add(b"A" * 10)
        >>> b.add(b"B" * 10)
        >>> len(b)
        20
        >>> b.get(1)
        b'A'
        >>> len(b)
        19
        >>> b.get(9999)
        b'AAAAAAAAABBBBBBBBBB'
        >>> len(b)
        0
        >>> b.get(1)
        b''

    Implementation Details:

        Implemented as a list. Bytes are added onto the end.
        The ``0th`` item in the buffer is the oldest item, and
        will be received first.
    """

    def __init__(self):
        self.data = []  # buffer
        self.size = 0  # length

    def __len__(self):
        """
        Examples:

            >>> b = Buffer()
            >>> b.add(b'lol')
            >>> len(b) == 3
            True
            >>> b.add(b'foobar')
            >>> len(b) == 9
            True
        """
        return self.size

    def __nonzero__(self):
        return len(self) > 0

    def __contains__(self, x):
        """
        Examples:

            >>> b = Buffer()
            >>> b.add(b'asdf')
            >>> b'x' in b
            False
            >>> b.add(b'x')
            >>> b'x' in b
            True
        """
        for b in self.data:
            if x in b:
                return True
        return False

    def index(self, x):
        """
        Examples:

            >>> b = Buffer()
            >>> b.add(b'asdf')
            >>> b.add(b'qwert')
            >>> b.index(b't') == len(b) - 1
            True
        """
        sofar = 0

        for b in self.data:
            if x in b:
                return sofar + b.index(x)
            sofar += len(b)

        raise IndexError()

    def add(self, data):
        """
        Adds data to the buffer.

        Arguments:
            data(bytes, Buffer): Data to add
        """
        # Fast path for ''
        if not data:
            return

        if isinstance(data, Buffer):
            self.size += data.size
            self.data += data.data
        else:
            self.size += len(data)
            self.data.append(data)

    def unget(self, data):
        """
        Places data at the front of the buffer.

        Arguments:
            data(bytes, Buffer): Data to place at the beginning of the buffer.

        Example:

            >>> b = Buffer()
            >>> b.add(b"hello")
            >>> b.add(b"world")
            >>> b.get(5)
            b'hello'
            >>> b.unget(b"goodbye")
            >>> b.get()
            b'goodbyeworld'
        """
        if isinstance(data, Buffer):
            self.data = data.data + self.data
            self.size += data.size
        else:
            self.data.insert(0, data)
            self.size += len(data)

    def get(self, want=float('inf')):
        """
        Retrieves bytes from the buffer.

        Arguments:
            want(int): Maximum number of bytes to fetch

        Returns:
            Data as string

        Example:

            >>> b = Buffer()
            >>> b.add(b'hello')
            >>> b.add(b'world')
            >>> b.get(1)
            b'h'
            >>> b.get()
            b'elloworld'
        """
        # Fast path, get all of the data
        if want >= self.size:
            data = b''.join(self.data)
            self.size = 0
            self.data = []
            return data

        # Slow path, find the correct-index chunk
        have = 0
        i = 0
        while want >= have:
            have += len(self.data[i])
            i += 1

        # Join the chunks, evict from the buffer
        data = b''.join(self.data[:i])
        self.data = self.data[i:]

        # If the last chunk puts us over the limit,
        # stick the extra back at the beginning.
        if have > want:
            extra = data[want:]
            data = data[:want]
            self.data.insert(0, extra)

        # Size update
        self.size -= len(data)

        return data
