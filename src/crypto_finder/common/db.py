from sqlalchemy import create_engine, Column, Integer, String, Text, JSON, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, declarative_base
from crypto_finder.common.config import settings
from crypto_finder.common.logging import log

try:
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False}
    )
    log.info("Database engine successfully created.")
except Exception as e:
    log.error(f"Database engine create karne me error: {e}")
    raise
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
class Binary(Base):
    """'binaries' table ko represent karta hai."""
    __tablename__ = "binaries"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, unique=True, index=True, nullable=False)
    filepath = Column(String, unique=True, nullable=False)
    filesize = Column(Integer)
    architecture = Column(String, nullable=True)

    analysis_results = relationship("AnalysisResult", back_populates="binary")

class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    binary_id = Column(Integer, ForeignKey("binaries.id"), nullable=False)
    analysis_type = Column(String, nullable=False)
    result_data = Column(JSON, nullable=False)

    binary = relationship("Binary", back_populates="analysis_results")


def create_db_and_tables():
    try:
        log.info("Database tables are being created")
        Base.metadata.create_all(bind=engine)
        log.success("Database tables successfully created.")
    except Exception as e:
        log.error(f"Database tables creation error: {e}")
