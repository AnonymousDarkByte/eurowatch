from sqlmodel import SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///eurowatch.db"

engine = create_engine(
    DATABASE_URL,
    echo=False,  # set to True temporarily if you want to see SQL queries
    connect_args={"check_same_thread": False}
)


def create_db():
    """Create all tables if they don't exist yet."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """Use this wherever you need to read/write the database."""
    with Session(engine) as session:
        yield session