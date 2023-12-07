import datetime
import os
from enum import Enum

from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker  # type: ignore

Base = declarative_base()
engine = create_engine(os.environ["DB_URL"])
Session = sessionmaker(bind=engine)


class ScanLogEntrySource(str, Enum):
    GUI = "gui"
    API = "api"


class NonexistentTranslationLogEntry(Base):  # type: ignore
    __tablename__ = "nonexistent_translation_logs"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    message = Column(String)


class ServerErrorLogEntry(Base):  # type: ignore
    __tablename__ = "server_error_logs"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    url = Column(String)
    error = Column(String)

    def __repr__(self) -> str:
        return ("<ServerErrorLogEntry(created_at='%s', url='%s'>") % (
            self.created_at,
            self.url,
        )


class DKIMImplementationMismatchLogEntry(Base):  # type: ignore
    __tablename__ = "dkim_implementation_mismatch_logs"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    message = Column(String)
    dkimpy_valid = Column(Boolean)
    opendkim_valid = Column(Boolean)

    def __repr__(self) -> str:
        return ("<DKIMImplementationMismatchLogEntry(created_at='%s', dkimpy_valid='%s', opendkim_valid='%s'>") % (
            self.created_at,
            self.dkimpy_valid,
            self.opendkim_valid,
        )


class ScanLogEntry(Base):  # type: ignore
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    envelope_domain = Column(String)
    from_domain = Column(String)
    dkim_domain = Column(String)
    message = Column(String)
    source = Column(String)
    client_ip = Column(String)
    client_user_agent = Column(String)
    check_options = Column(JSON)
    result = Column(JSON)
    error = Column(String)

    def __repr__(self) -> str:
        return ("<ScanLogEntry(domain='%s', source='%s', client_ip='%s', " "client_user_agent='%s')>") % (
            self.domain,
            self.source,
            self.client_ip,
            self.client_user_agent,
        )


Base.metadata.create_all(bind=engine)
