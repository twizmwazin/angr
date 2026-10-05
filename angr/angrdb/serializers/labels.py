# pylint:disable=unused-import
from __future__ import annotations

from typing import TYPE_CHECKING

from angr.angrdb.models import DbLabel
from angr.knowledge_plugins.labels import Labels

if TYPE_CHECKING:
    from angr.angrdb.models import DbKnowledgeBase
    from angr.knowledge_base import KnowledgeBase


class LabelsSerializer:
    """
    Serialize/unserialize labels to/from a database session.
    """

    @staticmethod
    def dump(session, db_kb: DbKnowledgeBase, labels: Labels):
        """

        :param session:
        :param db_kb:
        :param labels:
        :return:        None
        """

        for addr, name in labels.items():
            db_label = (
                session.query(DbLabel)
                .filter_by(
                    kb=db_kb,
                    addr=addr,
                )
                .scalar()
            )
            if db_label is not None:
                if name == db_label.name:
                    continue
                db_label.name = name
            else:
                db_label = DbLabel(
                    kb=db_kb,
                    addr=addr,
                    name=name,
                )
                session.add(db_label)

    @staticmethod
    def load(session, db_kb: DbKnowledgeBase, kb: KnowledgeBase):  # pylint:disable=unused-argument
        """

        :param session:
        :param db_kb:
        :param kb:
        :return:
        """

        db_labels = db_kb.labels
        labels = Labels(kb)

        for db_label in db_labels:
            labels[db_label.addr] = db_label.name

        return labels
