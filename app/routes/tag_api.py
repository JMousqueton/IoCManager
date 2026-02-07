"""Tag API routes - Autocomplete and management"""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from app.models.tag import Tag
from app import db

tag_api_bp = Blueprint('tag_api', __name__, url_prefix='/api/tags')


@tag_api_bp.route('/search')
@login_required
def search_tags():
    """
    Search tags for autocomplete

    Query params:
        q: Search query (partial tag name)
        limit: Max results (default 10)

    Returns:
        JSON array of matching tags
    """
    query = request.args.get('q', '').strip()
    limit = request.args.get('limit', 10, type=int)

    if not query:
        # Return most recent tags if no query
        tags = Tag.query.order_by(Tag.created_at.desc()).limit(limit).all()
    else:
        # Search tags by name (case-insensitive)
        tags = Tag.query.filter(
            Tag.name.ilike(f'%{query}%')
        ).order_by(Tag.name).limit(limit).all()

    return jsonify([tag.to_dict() for tag in tags])


@tag_api_bp.route('/all')
@login_required
def get_all_tags():
    """Get all tags"""
    tags = Tag.query.order_by(Tag.name).all()
    return jsonify([tag.to_dict() for tag in tags])


@tag_api_bp.route('/create', methods=['POST'])
@login_required
def create_tag():
    """
    Create a new tag

    Body:
        name: Tag name (required)
        description: Tag description (optional)
        color: Tag color hex code (optional)

    Returns:
        JSON of created tag or existing tag if already exists
    """
    data = request.get_json()

    if not data or 'name' not in data:
        return jsonify({'error': 'Tag name is required'}), 400

    tag_name = data['name'].strip().lower()

    if not tag_name:
        return jsonify({'error': 'Tag name cannot be empty'}), 400

    # Check if tag already exists
    existing_tag = Tag.query.filter_by(name=tag_name).first()
    if existing_tag:
        return jsonify(existing_tag.to_dict()), 200

    # Create new tag
    new_tag = Tag(
        name=tag_name,
        description=data.get('description'),
        color=data.get('color', '#6c757d')
    )

    try:
        db.session.add(new_tag)
        db.session.commit()
        return jsonify(new_tag.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


def get_or_create_tags(tag_names):
    """
    Get existing tags or create new ones

    Args:
        tag_names: List of tag names or comma-separated string

    Returns:
        List of Tag objects
    """
    # Handle string input (comma-separated)
    if isinstance(tag_names, str):
        tag_names = [t.strip().lower() for t in tag_names.split(',') if t.strip()]

    # Handle list input
    elif isinstance(tag_names, list):
        tag_names = [t.strip().lower() for t in tag_names if isinstance(t, str) and t.strip()]

    else:
        return []

    if not tag_names:
        return []

    tags = []

    for tag_name in tag_names:
        # Check if tag exists
        tag = Tag.query.filter_by(name=tag_name).first()

        if not tag:
            # Create new tag
            tag = Tag(name=tag_name)
            db.session.add(tag)
            try:
                db.session.commit()
            except:
                db.session.rollback()
                # Try to get it again in case of race condition
                tag = Tag.query.filter_by(name=tag_name).first()

        if tag:
            tags.append(tag)

    return tags
