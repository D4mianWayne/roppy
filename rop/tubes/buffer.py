#!/usr/bin/env python3


class Buffer(Exception):
    """
    A Buffer class to work as a reservoir in order
    to store and help with the control flow of the
    `tube` and `process`
    """

    def __init__(self):
        self.data = []  # buffer
        self.size = 0  # length

    def __len__(self):
        """
        Returns length of the buffer.
        """
        return self.size

    def __nonzero__(self):
        return len(self) > 0

    def __contains__(self, x):
        """
        Check if a string exits in the buffer or not.
        """
        for b in self.data:
            if x in b:
                return True
        return False

    def index(self, x):
        """
        Returns the index of the character in a string.
        """
        sofar = 0

        for b in self.data:
            if x in b:
                return sofar + b.index(x)
            sofar += len(b)

        raise IndexError()

    def add(self, data):
        """
        Appends the data t the buffer.
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
