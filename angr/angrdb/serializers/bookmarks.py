from __future__ import annotations

from typing import TYPE_CHECKING

from angr.angrdb.models import DbBookmark
from angr.knowledge_plugins.bookmarks import Bookmark, Bookmarks

if TYPE_CHECKING:
    from angr.angrdb.models import DbKnowledgeBase
    from angr.knowledge_base import KnowledgeBase


class BookmarksSerializer:
    """
    Serialize/unserialize bookmarks to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, bookmarks: Bookmarks):
        """

        :param session:
        :param db_kb:
        :param bookmarks:
        :return:                        None
        """

        # bookmark lists are small; rewrite them wholesale so removals persist
        for db_bookmark in list(db_kb.bookmarks):
            session.delete(db_bookmark)
        for bookmark in bookmarks:
            session.add(
                DbBookmark(
                    kb=db_kb,
                    addr=bookmark.addr,
                    label=bookmark.label,
                    created_at=bookmark.created_at,
                )
            )

    @staticmethod
    def load(session, db_kb: DbKnowledgeBase, kb: KnowledgeBase):  # pylint:disable=unused-argument
        """

        :param session:
        :param db_kb:
        :param kb:
        :return:
        """

        bookmarks = Bookmarks(kb)
        for db_bookmark in db_kb.bookmarks:
            bookmarks.append(Bookmark(db_bookmark.addr, db_bookmark.label or "", db_bookmark.created_at))
        return bookmarks
