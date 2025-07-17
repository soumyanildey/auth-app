import time
from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError
from psycopg2 import OperationalError as Psycopg2OpError


class Command(BaseCommand):
    '''Wait for the DB connection to established'''

    def handle(self, *args, **kwargs):
        self.stdout.write(
            "Waiting for all configured databases to become available...")

        for alias in connections:
            db_up = False
            self.stdout.write(f"Checking connection for '{alias}' database...")

            while not db_up:
                try:
                    connections[alias].cursor()
                    db_up = True
                except (OperationalError, Psycopg2OpError):
                    self.stdout.write(
                        f"'{alias}' database unavailable, retrying in 1 second...")
                    time.sleep(1)

            self.stdout.write(self.style.SUCCESS(
                f"'{alias}' database connection established."))

        self.stdout.write(self.style.SUCCESS(
            "All configured databases are available."))
