"""
sentinel/core/models.py
SQLAlchemy ORM models for scans, findings, and reports.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum

from sqlalchemy import (
    JSON, Column, DateTime, Enum, ForeignKey, String, Text, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

from sentinel.core.config import config


class Base(DeclarativeBase):
    pass


class ScanStatus(str, PyEnum):
    PENDING   = "pending"
    RUNNING   = "running"
    ANALYZING = "analyzing"
    COMPLETE  = "complete"
    FAILED    = "failed"


class Severity(str, PyEnum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Scan(Base):
    __tablename__ = "scans"

    id          = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target      = Column(String(255), nullable=False)
    status      = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    llm_backend = Column(String(32), nullable=True)
    raw_results = Column(JSON, default=dict)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                         onupdate=lambda: datetime.now(timezone.utc))

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports  = relationship("Report",  back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "target":      self.target,
            "status":      self.status,
            "llm_backend": self.llm_backend,
            "raw_results": self.raw_results,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
            "updated_at":  self.updated_at.isoformat() if self.updated_at else None,
            "findings":    [f.to_dict() for f in self.findings],
        }


class Finding(Base):
    __tablename__ = "findings"

    id          = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id     = Column(String(36), ForeignKey("scans.id"), nullable=False)
    title       = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity    = Column(Enum(Severity), default=Severity.INFO, nullable=False)
    module      = Column(String(64), nullable=True)
    evidence    = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    cvss_score  = Column(String(8), nullable=True)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "scan_id":     self.scan_id,
            "title":       self.title,
            "description": self.description,
            "severity":    self.severity,
            "module":      self.module,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "cvss_score":  self.cvss_score,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
        }


class Report(Base):
    __tablename__ = "reports"

    id         = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id    = Column(String(36), ForeignKey("scans.id"), nullable=False)
    file_path  = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("Scan", back_populates="reports")

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "scan_id":    self.scan_id,
            "file_path":  self.file_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


engine       = create_engine(config.database_url, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
