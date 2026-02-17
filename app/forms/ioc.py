"""IOC management forms"""

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, IntegerField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Length, NumberRange, Optional, ValidationError
from flask_wtf.file import FileAllowed


class IOCForm(FlaskForm):
    """Form for creating/editing IOCs"""

    value = TextAreaField('IOC Value', validators=[
        DataRequired(message='IOC value is required'),
        Length(max=10000, message='IOC value is too long')
    ])
    ioc_type_id = SelectField('Type', coerce=int, validators=[
        DataRequired(message='IOC type is required')
    ])
    description = TextAreaField('Description', validators=[
        Length(max=5000, message='Description is too long')
    ])
    severity = SelectField('Severity', choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical')
    ], validators=[DataRequired()])
    confidence = IntegerField('Confidence (0-100)', validators=[
        NumberRange(min=0, max=100, message='Confidence must be between 0 and 100')
    ], default=50)
    source = StringField('Source', validators=[
        Length(max=255, message='Source is too long')
    ])
    tlp = SelectField('TLP (Traffic Light Protocol)', choices=[
        ('WHITE', 'WHITE - Unlimited disclosure'),
        ('GREEN', 'GREEN - Community disclosure'),
        ('AMBER', 'AMBER - Limited disclosure'),
        ('RED', 'RED - Personal for named recipients only')
    ], validators=[DataRequired()])
    tags = StringField('Tags (comma-separated)', validators=[
        Length(max=500, message='Tags field is too long')
    ])
    operating_system_id = SelectField('Operating System', coerce=int, validators=[Optional()])
    notes = TextAreaField('Notes', validators=[
        Length(max=5000, message='Notes are too long')
    ])
    status = SelectField('Lifecycle Status', choices=[
        ('review', 'To be reviewed'),
        ('active', 'Active'),
        ('draft', 'Draft (submit later)'),
    ], validators=[Optional()], default='review')
    is_active = BooleanField('Active')
    false_positive = BooleanField('Mark as False Positive')
    expiration_days = IntegerField(
        'Expires in (days)',
        validators=[
            Optional(),
            NumberRange(min=1, max=3650, message='Expiration must be between 1 and 3650 days')
        ],
        description='Leave empty for no expiration'
    )
    submit = SubmitField('Save IOC')


class IOCSearchForm(FlaskForm):
    """Form for searching IOCs"""

    query = StringField('Search', validators=[Optional()])
    ioc_type_id = SelectField('Type', coerce=int, validators=[Optional()])
    severity = SelectField('Severity', choices=[
        ('', 'All'),
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical')
    ], validators=[Optional()])
    tlp = SelectField('TLP', choices=[
        ('', 'All'),
        ('WHITE', 'WHITE'),
        ('GREEN', 'GREEN'),
        ('AMBER', 'AMBER'),
        ('RED', 'RED')
    ], validators=[Optional()])
    is_active = SelectField('Status', choices=[
        ('', 'All'),
        ('1', 'Active'),
        ('0', 'Inactive')
    ], validators=[Optional()])
    lifecycle_status = SelectField('Lifecycle', choices=[
        ('', 'All'),
        ('draft', 'Draft'),
        ('review', 'In Review'),
        ('active', 'Active'),
        ('archived', 'Archived'),
    ], validators=[Optional()])
    needs_review = SelectField('Review Status', choices=[
        ('', 'All'),
        ('1', 'To be reviewed'),
        ('0', 'Not for review')
    ], validators=[Optional()])
    submit = SubmitField('Search')


class IOCBulkImportForm(FlaskForm):
    """Form for bulk importing IOCs"""

    file = FileField('CSV/JSON File', validators=[
        DataRequired(message='Please select a file'),
        FileAllowed(['csv', 'json'], 'Only CSV and JSON files are allowed')
    ])
    ioc_type_id = SelectField('Default IOC Type', coerce=int, validators=[
        DataRequired(message='Default IOC type is required')
    ])
    severity = SelectField('Default Severity', choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical')
    ], validators=[DataRequired()])
    tlp = SelectField('Default TLP', choices=[
        ('WHITE', 'WHITE'),
        ('GREEN', 'GREEN'),
        ('AMBER', 'AMBER'),
        ('RED', 'RED')
    ], validators=[DataRequired()])
    source = StringField('Source', validators=[
        Length(max=255, message='Source is too long')
    ])
    submit = SubmitField('Import IOCs')
