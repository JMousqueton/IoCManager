"""Markdown rendering utilities with XSS protection"""

import markdown
import bleach
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.nl2br import Nl2BrExtension


# Allowed HTML tags after markdown conversion
ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'strike', 'del', 'code', 'pre',
    'a', 'img', 'ul', 'ol', 'li', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'div', 'span', 'hr'
]

# Allowed HTML attributes
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'target', 'rel'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    'code': ['class'],
    'pre': ['class'],
    'div': ['class'],
    'span': ['class'],
    'th': ['align'],
    'td': ['align']
}

# URL protocols allowed in links
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def render_markdown(text):
    """
    Convert markdown text to safe HTML

    Args:
        text (str): Markdown formatted text

    Returns:
        str: Safe HTML string
    """
    if not text:
        return ''

    # Configure markdown extensions
    md = markdown.Markdown(extensions=[
        'extra',  # Tables, footnotes, attribute lists, etc.
        'codehilite',  # Syntax highlighting for code blocks
        'fenced_code',  # GitHub-style fenced code blocks
        'nl2br',  # Convert newlines to <br>
        'sane_lists',  # Better list handling
        'smarty',  # Smart quotes and dashes
        'toc',  # Table of contents
    ], extension_configs={
        'codehilite': {
            'linenums': False,
            'guess_lang': True,
            'css_class': 'highlight'
        }
    })

    # Convert markdown to HTML
    html = md.convert(text)

    # Sanitize HTML to prevent XSS attacks
    clean_html = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True
    )

    # Auto-link URLs
    clean_html = bleach.linkify(
        clean_html,
        callbacks=[],
        skip_tags=['pre', 'code']
    )

    return clean_html


def strip_markdown(text, max_length=200):
    """
    Strip markdown formatting and return plain text

    Args:
        text (str): Markdown formatted text
        max_length (int): Maximum length of output

    Returns:
        str: Plain text without markdown formatting
    """
    if not text:
        return ''

    # Convert to HTML then strip tags
    html = render_markdown(text)
    plain_text = bleach.clean(html, tags=[], strip=True)

    # Truncate if needed
    if len(plain_text) > max_length:
        return plain_text[:max_length] + '...'

    return plain_text
