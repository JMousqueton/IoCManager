"""
Migration script to add domain_enrichment_cache table
Run this after adding the DomainEnrichmentCache model
"""

from app import create_app, db

def migrate():
    """Create domain_enrichment_cache table"""
    app = create_app()

    with app.app_context():
        # Import the model to ensure it's registered
        from app.models import DomainEnrichmentCache

        # Create the table
        db.create_all()
        print("✓ Created domain_enrichment_cache table")

if __name__ == '__main__':
    migrate()
