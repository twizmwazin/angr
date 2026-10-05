from __future__ import annotations

from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from google.protobuf.message import Message


class Serializable:
    """
    The base class of all protobuf-serializable classes in angr.
    """

    __slots__ = ()

    @classmethod
    def _get_cmsg(cls):
        """
        Get a cmessage object.

        :return:    The correct cmessage object.
        """

        raise NotImplementedError

    def serialize_to_cmessage(self) -> Message:
        """
        Serialize the class object and returns a protobuf cmessage object.

        :return:    A protobuf cmessage object.
        """

        raise NotImplementedError

    def serialize(self) -> bytes:
        """
        Serialize the class object and returns a bytes object.

        :return:    A bytes object.
        """

        return self.serialize_to_cmessage().SerializeToString()

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs) -> Self:
        """
        Parse a protobuf cmessage and create a class object.

        :param cmsg:    The probobuf cmessage object.
        :return:        A unserialized class object.
        """

        raise NotImplementedError

    @classmethod
    def parse(cls, s: bytes, **kwargs) -> Self:
        """
        Parse a bytes object and create a class object.

        :param s:       A bytes object.
        :return:        A class object.
        """

        pb2_obj = cls._get_cmsg()
        pb2_obj.ParseFromString(s)

        return cls.parse_from_cmessage(pb2_obj, **kwargs)
