"""Admin forms"""

from flask_wtf import FlaskForm
from wtforms import SelectField, DateField, SubmitField
from wtforms.validators import Optional


class AuditLogSearchForm(FlaskForm):
    """Form for searching audit logs"""

    resource_type = SelectField('Resource Type', choices=[
        ('', 'All'),
        ('IOC', 'IOC'),
        ('User', 'User'),
        ('Tag', 'Tag'),
        ('Configuration', 'Configuration')
    ], validators=[Optional()])

    action = SelectField('Action', choices=[
        ('', 'All'),
        ('CREATE', 'CREATE'),
        ('UPDATE', 'UPDATE'),
        ('DELETE', 'DELETE'),
        ('VIEW', 'VIEW'),
        ('LOGIN', 'LOGIN'),
        ('LOGOUT', 'LOGOUT'),
        ('ENRICH', 'ENRICH'),
        ('EXPORT', 'EXPORT'),
        ('SEARCH', 'SEARCH')
    ], validators=[Optional()])

    user_id = SelectField('User', coerce=int, validators=[Optional()])

    date_from = DateField('From Date', validators=[Optional()], format='%Y-%m-%d')
    date_to = DateField('To Date', validators=[Optional()], format='%Y-%m-%d')

    submit = SubmitField('Search')
