"""sign and verify for request/response exchanges — not implemented in the initial snapshot."""


class NotImplementedEngine(NotImplementedError):
    pass


def verify(exchange, keys, policy):
    raise NotImplementedEngine("relreq.verify is not implemented")


def sign(exchange, keys, policy):
    raise NotImplementedEngine("relreq.sign is not implemented")
