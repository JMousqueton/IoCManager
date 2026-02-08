"""IOC management routes blueprint"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.ioc import IOC, IOCType
from app.models.tag import Tag
from app.models.audit import AuditLog
from app.forms.ioc import IOCForm, IOCSearchForm, IOCBulkImportForm
from sqlalchemy import or_

ioc_bp = Blueprint('ioc', __name__)


@ioc_bp.route('/')
@login_required
def list():
    """List all IOCs with search/filter"""

    form = IOCSearchForm(request.args, meta={'csrf': False})

    # Populate IOC type choices
    types = IOCType.query.all()
    form.ioc_type_id.choices = [(0, 'All Types')] + [(t.id, t.name) for t in types]

    # Base query
    query = IOC.query

    # Apply filters
    if form.query.data:
        search_term = f'%{form.query.data}%'
        query = query.filter(or_(
            IOC.value.ilike(search_term),
            IOC.description.ilike(search_term),
            IOC.notes.ilike(search_term)
        ))

    if form.ioc_type_id.data and form.ioc_type_id.data != 0:
        query = query.filter_by(ioc_type_id=form.ioc_type_id.data)

    if form.severity.data:
        query = query.filter_by(severity=form.severity.data)

    if form.tlp.data:
        query = query.filter_by(tlp=form.tlp.data)

    if form.is_active.data:
        query = query.filter_by(is_active=bool(int(form.is_active.data)))

    if form.needs_review.data:
        query = query.filter_by(needs_review=bool(int(form.needs_review.data)))

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 25
    pagination = query.order_by(IOC.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    iocs = pagination.items

    from datetime import datetime
    return render_template('ioc/list.html',
                           iocs=iocs,
                           pagination=pagination,
                           form=form,
                           now=datetime.utcnow)


@ioc_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create new IOC"""

    # Only Users and Admins can create IOCs
    if current_user.is_viewer():
        flash('You do not have permission to create IOCs.', 'danger')
        return redirect(url_for('ioc.list'))

    form = IOCForm()

    # Populate IOC type choices
    types = IOCType.query.all()
    form.ioc_type_id.choices = [(t.id, t.name) for t in types]

    if form.validate_on_submit():
        ioc = IOC(
            value=form.value.data,
            ioc_type_id=form.ioc_type_id.data,
            description=form.description.data,
            severity=form.severity.data,
            confidence=form.confidence.data,
            source=form.source.data,
            tlp=form.tlp.data,
            notes=form.notes.data,
            is_active=form.is_active.data,
            false_positive=form.false_positive.data,
            created_by=current_user.id
        )

        # Handle expiration
        if form.expiration_days.data:
            ioc.set_expiration(form.expiration_days.data)

        # Handle tags (auto-create if they don't exist)
        if form.tags.data:
            from app.routes.tag_api import get_or_create_tags
            tags = get_or_create_tags(form.tags.data)
            for tag in tags:
                ioc.add_tag(tag)

        db.session.add(ioc)
        db.session.commit()

        flash(f'IOC created successfully: {ioc.value[:50]}', 'success')
        return redirect(url_for('ioc.detail', id=ioc.id))

    # Set defaults
    form.is_active.data = True
    form.confidence.data = 50
    form.severity.data = 'Medium'
    form.tlp.data = 'WHITE'

    return render_template('ioc/create.html', form=form)


@ioc_bp.route('/<int:id>')
@login_required
def detail(id):
    """View IOC details"""
    from datetime import datetime
    from app.models.comment import Comment

    ioc = IOC.query.get_or_404(id)

    # Get root comments (not replies) ordered by created_at descending
    root_comments = Comment.query.filter_by(
        ioc_id=id,
        parent_id=None
    ).order_by(Comment.created_at.desc()).all()

    return render_template('ioc/detail.html', ioc=ioc, now=datetime.utcnow, root_comments=root_comments)


@ioc_bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    """Edit IOC"""

    ioc = IOC.query.get_or_404(id)

    # Check permissions
    if not current_user.can_modify_ioc(ioc):
        flash('You do not have permission to edit this IOC.', 'danger')
        return redirect(url_for('ioc.detail', id=id))

    form = IOCForm()

    # Populate IOC type choices
    types = IOCType.query.all()
    form.ioc_type_id.choices = [(t.id, t.name) for t in types]

    if form.validate_on_submit():
        ioc.value = form.value.data
        ioc.ioc_type_id = form.ioc_type_id.data
        ioc.description = form.description.data
        ioc.severity = form.severity.data
        ioc.confidence = form.confidence.data
        ioc.source = form.source.data
        ioc.tlp = form.tlp.data
        ioc.notes = form.notes.data
        ioc.is_active = form.is_active.data
        ioc.false_positive = form.false_positive.data
        ioc.updated_by = current_user.id

        # Handle expiration
        from flask import request
        if form.expiration_days.data:
            ioc.set_expiration(form.expiration_days.data)
        elif 'expiration_days' in request.form and not form.expiration_days.data:
            # Field exists but is empty - remove expiration
            ioc.expires_at = None
            ioc.expired_reason = None

        # Handle tags
        # Clear existing tags
        ioc.tags = []

        # Handle tags (auto-create if they don't exist)
        if form.tags.data:
            from app.routes.tag_api import get_or_create_tags
            tags = get_or_create_tags(form.tags.data)
            for tag in tags:
                ioc.add_tag(tag)

        db.session.commit()

        flash('IOC updated successfully.', 'success')
        return redirect(url_for('ioc.detail', id=id))

    # Populate form with existing data
    form.value.data = ioc.value
    form.ioc_type_id.data = ioc.ioc_type_id
    form.description.data = ioc.description
    form.severity.data = ioc.severity
    form.confidence.data = ioc.confidence
    form.source.data = ioc.source
    form.tlp.data = ioc.tlp
    form.notes.data = ioc.notes
    form.is_active.data = ioc.is_active
    form.false_positive.data = ioc.false_positive
    form.tags.data = ', '.join([tag.name for tag in ioc.tags])

    # Populate expiration field (remaining days)
    from datetime import datetime
    if ioc.expires_at:
        remaining_days = (ioc.expires_at - datetime.utcnow()).days
        form.expiration_days.data = max(1, remaining_days)

    return render_template('ioc/edit.html', form=form, ioc=ioc)


@ioc_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    """Delete IOC"""

    ioc = IOC.query.get_or_404(id)

    # Check permissions
    if not current_user.can_delete_ioc(ioc):
        flash('You do not have permission to delete this IOC.', 'danger')
        return redirect(url_for('ioc.detail', id=id))

    db.session.delete(ioc)
    db.session.commit()

    flash('IOC deleted successfully.', 'success')
    return redirect(url_for('ioc.list'))


@ioc_bp.route('/<int:id>/toggle-review', methods=['POST'])
@login_required
def toggle_review(id):
    """Toggle review status for an IOC"""

    ioc = IOC.query.get_or_404(id)

    # Toggle the review flag
    ioc.needs_review = not ioc.needs_review

    # Audit log
    log = AuditLog(
        user_id=current_user.id,
        action='UPDATE',
        resource_type='IOC',
        resource_id=ioc.id,
        details=f'{"Marked" if ioc.needs_review else "Unmarked"} IOC for review'
    )
    db.session.add(log)
    db.session.commit()

    if ioc.needs_review:
        flash('IOC marked for review. Any user can now edit this IOC.', 'success')
    else:
        flash('IOC unmarked for review. Normal edit permissions restored.', 'success')

    return redirect(url_for('ioc.detail', id=id))


@ioc_bp.route('/bulk-import', methods=['GET', 'POST'])
@login_required
def bulk_import():
    """Bulk import IOCs from CSV/JSON"""

    # Only Users and Admins can import IOCs
    if current_user.is_viewer():
        flash('You do not have permission to import IOCs.', 'danger')
        return redirect(url_for('ioc.list'))

    form = IOCBulkImportForm()

    # Populate IOC type choices
    types = IOCType.query.all()
    form.ioc_type_id.choices = [(t.id, t.name) for t in types]

    if form.validate_on_submit():
        # Handle file upload and import
        # This is a placeholder - actual implementation would process the file
        flash('Bulk import feature coming soon!', 'info')
        return redirect(url_for('ioc.list'))

    form.severity.data = 'Medium'
    form.tlp.data = 'WHITE'

    return render_template('ioc/bulk_import.html', form=form)


@ioc_bp.route('/<int:id>/enrich', methods=['POST'])
@login_required
def enrich(id):
    """Enrich IOC with GeoIP data or VirusTotal data"""

    ioc = IOC.query.get_or_404(id)

    # Check permissions
    if not current_user.can_modify_ioc(ioc):
        flash('You do not have permission to enrich this IOC.', 'danger')
        return redirect(url_for('ioc.detail', id=id))

    ioc_type_name = ioc.ioc_type.name

    # Handle IP address enrichment (GeoIP)
    if ioc_type_name in ['IPv4', 'IPv6']:
        from app.services.geoip import get_geoip_service

        geoip = get_geoip_service()

        # Check if service is available
        if not geoip.is_available():
            flash('GeoIP service is not available. Please download MaxMind databases first.', 'danger')
            return redirect(url_for('ioc.detail', id=id))

        # Enrich the IP address
        try:
            ip_address = ioc.value.strip()
            enrichment_data = geoip.enrich_ipv4(ip_address)

            if enrichment_data:
                # Generate summary
                summary = geoip.get_summary(enrichment_data)

                # Add ASN information
                asn_data = geoip.enrich_asn(ip_address)
                if asn_data:
                    enrichment_data['asn'] = asn_data

                # Store enrichment data in JSON format
                ioc.set_enrichment(enrichment_data)

                db.session.commit()

                # Log the enrichment
                from app.models.audit import AuditLog
                log = AuditLog(
                    user_id=current_user.id,
                    action='ENRICH',
                    resource_type='IOC',
                    resource_id=ioc.id,
                    details=f'Enriched IOC with GeoIP data: {summary}'
                )
                db.session.add(log)
                db.session.commit()

                flash(f'IOC enriched successfully! Location: {summary}', 'success')
            else:
                flash('No geolocation data found for this IP address.', 'warning')

        except Exception as e:
            flash(f'Error enriching IOC: {str(e)}', 'danger')

    # Handle file hash enrichment (VirusTotal)
    elif ioc_type_name in ['SHA256', 'MD5', 'SHA1']:
        from app.services.virustotal import VTService

        vt_service = VTService()

        # Check if service is available
        if not vt_service.api_key or vt_service.api_key == 'your-virustotal-api-key-here':
            flash('VirusTotal API key not configured. Please add VIRUSTOTAL_API_KEY to .env file.', 'danger')
            return redirect(url_for('ioc.detail', id=id))

        # Enrich the file hash
        try:
            hash_value = ioc.value.strip()
            enrichment_data = vt_service.get_hash_report(hash_value)

            if enrichment_data and enrichment_data.get('status') == 'success':
                # Store enrichment data in JSON format
                ioc.set_enrichment(enrichment_data)

                db.session.commit()

                # Log the enrichment
                from app.models.audit import AuditLog

                detection_rate = enrichment_data.get('detection_rate', 'N/A')
                threat_class = enrichment_data.get('threat_classification', 'Unknown')

                log = AuditLog(
                    user_id=current_user.id,
                    action='ENRICH',
                    resource_type='IOC',
                    resource_id=ioc.id,
                    details=f'Enriched IOC with VirusTotal data: {detection_rate} detections, classified as {threat_class}'
                )
                db.session.add(log)
                db.session.commit()

                flash(f'IOC enriched successfully! Detection: {detection_rate}, Classification: {threat_class}', 'success')

            elif enrichment_data and enrichment_data.get('status') == 'not_found':
                flash('Hash not found in VirusTotal database.', 'warning')

            elif enrichment_data and enrichment_data.get('status') == 'rate_limited':
                flash('VirusTotal API rate limit exceeded. Please try again later.', 'warning')

            elif enrichment_data and enrichment_data.get('status') == 'error':
                error_msg = enrichment_data.get('error', 'Unknown error')
                flash(f'VirusTotal API error: {error_msg}', 'danger')

            else:
                flash('Could not retrieve VirusTotal data for this hash.', 'warning')

        except Exception as e:
            flash(f'Error enriching IOC: {str(e)}', 'danger')

    # Handle URL enrichment (URLScan.io + VirusTotal + Header Analysis)
    elif ioc_type_name in ['URL']:
        from app.services.urlscan import URLScanService
        from app.services.virustotal import VTService
        from app.services.url_enrichment import URLEnrichmentService

        url_value = ioc.value.strip()
        combined_enrichment = {
            'urlscan': None,
            'virustotal': None,
            'url_headers': None,
            'status': 'partial'  # Will be updated based on results
        }
        success_count = 0
        messages = []

        # Query URL Headers/Server Info
        try:
            url_enrichment_service = URLEnrichmentService()
            url_header_data = url_enrichment_service.enrich_url(url_value, ioc_id=ioc.id)

            if url_header_data and url_header_data.get('status') == 'success':
                combined_enrichment['url_headers'] = url_header_data
                success_count += 1

                server = url_header_data.get('server', 'Unknown')
                status_code = url_header_data.get('status_code', 'N/A')
                technologies = url_header_data.get('technologies', [])
                tech_str = ', '.join(technologies[:3]) if technologies else 'None detected'
                messages.append(f'Headers: HTTP {status_code}, Server: {server[:30]}, Tech: {tech_str}')

            elif url_header_data and url_header_data.get('status') == 'error':
                error_msg = url_header_data.get('error', 'Unknown error')
                messages.append(f'Headers: Error - {error_msg[:50]}')

        except Exception as e:
            logger.error(f"URL header enrichment error: {e}")
            messages.append(f'Headers: Error - {str(e)[:50]}')

        # Query URLScan.io
        try:
            urlscan_service = URLScanService()

            if urlscan_service.api_key and urlscan_service.api_key != 'your-urlscan-api-key-here':
                urlscan_data = urlscan_service.get_url_report(url_value)

                if urlscan_data and urlscan_data.get('status') == 'success':
                    combined_enrichment['urlscan'] = urlscan_data
                    success_count += 1

                    domain = urlscan_data.get('domain', 'N/A')
                    verdict_score = urlscan_data.get('verdicts', {}).get('overall', 0)
                    is_malicious = urlscan_data.get('verdicts', {}).get('malicious', False)
                    verdict_text = 'Malicious' if is_malicious else 'Clean'
                    messages.append(f'URLScan: {domain}, {verdict_text}')

                elif urlscan_data and urlscan_data.get('status') == 'pending':
                    messages.append('URLScan: Scan in progress (try again in 10-15 seconds)')

                elif urlscan_data and urlscan_data.get('status') == 'rate_limited':
                    messages.append('URLScan: Rate limit exceeded')

        except Exception as e:
            logger.error(f"URLScan enrichment error: {e}")
            messages.append(f'URLScan: Error - {str(e)}')

        # Query VirusTotal
        try:
            vt_service = VTService()

            if vt_service.api_key:
                vt_data = vt_service.get_url_report(url_value)

                if vt_data and vt_data.get('status') == 'success':
                    combined_enrichment['virustotal'] = vt_data
                    success_count += 1

                    detection_rate = vt_data.get('detection_rate', 'N/A')
                    threat_class = vt_data.get('threat_classification', 'Unknown')
                    messages.append(f'VirusTotal: {detection_rate} detections, {threat_class}')

                elif vt_data and vt_data.get('status') == 'not_found':
                    messages.append('VirusTotal: URL not found in database')

                elif vt_data and vt_data.get('status') == 'rate_limited':
                    messages.append('VirusTotal: Rate limit exceeded')

        except Exception as e:
            logger.error(f"VirusTotal URL enrichment error: {e}")
            messages.append(f'VirusTotal: Error - {str(e)}')

        # Extract and enrich IP addresses with GeoIP
        ip_addresses = []

        # Get IP from URLScan
        if combined_enrichment.get('urlscan'):
            ip = combined_enrichment['urlscan'].get('ip')
            if ip and ip not in ip_addresses:
                ip_addresses.append(ip)

        # Get IP from VirusTotal (might be in different location)
        if combined_enrichment.get('virustotal'):
            # VT might have IP in different fields, we can add extraction if needed
            pass

        # Enrich IPs with GeoIP
        if ip_addresses:
            from app.services.geoip import get_geoip_service

            geoip_service = get_geoip_service()
            if geoip_service.is_available():
                combined_enrichment['geoip'] = {}

                for ip in ip_addresses:
                    try:
                        # Determine if IPv4 or IPv6
                        import ipaddress
                        ip_obj = ipaddress.ip_address(ip)

                        if isinstance(ip_obj, ipaddress.IPv4Address):
                            geoip_data = geoip_service.enrich_ipv4(ip)
                        else:
                            geoip_data = geoip_service.enrich_ipv6(ip)

                        if geoip_data:
                            combined_enrichment['geoip'][ip] = geoip_data

                            # Get ASN data
                            asn_data = geoip_service.enrich_asn(ip)
                            if asn_data:
                                combined_enrichment['geoip'][ip]['asn'] = asn_data

                            # Add to messages
                            country = geoip_data.get('country', {}).get('name', 'Unknown')
                            city = geoip_data.get('city', {}).get('name', '')
                            location_str = f"{city}, {country}" if city else country
                            messages.append(f'GeoIP ({ip}): {location_str}')

                    except Exception as e:
                        logger.error(f"GeoIP enrichment error for {ip}: {e}")

        # Store combined enrichment data if we got any results
        if success_count > 0:
            combined_enrichment['status'] = 'success'
            ioc.set_enrichment(combined_enrichment)
            db.session.commit()

            # Log the enrichment
            from app.models.audit import AuditLog

            log = AuditLog(
                user_id=current_user.id,
                action='ENRICH',
                resource_type='IOC',
                resource_id=ioc.id,
                details=f'Enriched URL with {success_count} source(s): {", ".join(messages)}'
            )
            db.session.add(log)
            db.session.commit()

            flash(f'IOC enriched successfully! {" | ".join(messages)}', 'success')

        else:
            flash(f'Could not retrieve enrichment data. {" | ".join(messages)}', 'warning')

    # Handle Domain enrichment (WHOIS, DNS records)
    elif ioc_type_name in ['Domain']:
        from app.services.domain_enrichment import DomainEnrichmentService

        domain_value = ioc.value.strip()

        try:
            enrichment_service = DomainEnrichmentService()
            enrichment_data = enrichment_service.enrich_domain(domain_value)

            if enrichment_data and enrichment_data.get('status') == 'success':
                # Store enrichment data in JSON format
                ioc.set_enrichment(enrichment_data)
                db.session.commit()

                # Log the enrichment
                from app.models.audit import AuditLog
                log = AuditLog(
                    user_id=current_user.id,
                    action='ENRICH',
                    resource_type='IOC',
                    resource_id=ioc.id,
                    details=f'Enriched domain with WHOIS and DNS data'
                )
                db.session.add(log)
                db.session.commit()

                # Build success message
                messages = []
                if enrichment_data.get('registrar'):
                    messages.append(f"Registrar: {enrichment_data['registrar']}")
                if enrichment_data.get('registration_date'):
                    messages.append(f"Registered: {enrichment_data['registration_date'][:10]}")
                if enrichment_data.get('mx_records'):
                    messages.append(f"MX records: {len(enrichment_data['mx_records'])}")
                if enrichment_data.get('txt_records'):
                    messages.append(f"TXT records: {len(enrichment_data['txt_records'])}")

                flash(f'Domain enriched successfully. {" | ".join(messages)}', 'success')

            elif enrichment_data and enrichment_data.get('status') == 'error':
                error_msg = enrichment_data.get('error', 'Unknown error')
                flash(f'Domain enrichment error: {error_msg}', 'danger')

            else:
                flash('Could not retrieve domain enrichment data.', 'warning')

        except Exception as e:
            logger.error(f"Domain enrichment error for {domain_value}: {e}")
            flash(f'Error enriching domain: {str(e)}', 'danger')

    else:
        flash(f'Enrichment not supported for IOC type: {ioc_type_name}', 'warning')

    return redirect(url_for('ioc.detail', id=id))


@ioc_bp.route('/<int:id>/extend-expiration', methods=['POST'])
@login_required
def extend_expiration(id):
    """Extend IOC expiration"""

    ioc = IOC.query.get_or_404(id)

    # Check permissions
    if not current_user.can_modify_ioc(ioc):
        flash('You do not have permission to modify this IOC.', 'danger')
        return redirect(url_for('ioc.detail', id=id))

    from flask import request
    additional_days = request.form.get('additional_days', type=int, default=30)

    ioc.extend_expiration(additional_days)
    db.session.commit()

    # Audit log
    from app.models.audit import AuditLog
    log = AuditLog(
        user_id=current_user.id,
        action='UPDATE',
        resource_type='IOC',
        resource_id=ioc.id,
        details=f'Extended IOC expiration by {additional_days} days. New expiration: {ioc.expires_at}'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'IOC expiration extended by {additional_days} days.', 'success')
    return redirect(url_for('ioc.detail', id=id))



@ioc_bp.route('/<int:id>/generate-yara')
@login_required
def generate_yara(id):
    """Generate YARA rule for an IOC"""
    from app.services.yara_generator import YaraGenerator
    
    ioc = IOC.query.get_or_404(id)
    
    # Generate YARA rule
    yara_rule = YaraGenerator.generate_rule(ioc)
    
    # Return as JSON for AJAX request
    return jsonify({
        'success': True,
        'yara_rule': yara_rule,
        'ioc_id': ioc.id,
        'ioc_value': ioc.value[:50] + '...' if len(ioc.value) > 50 else ioc.value
    })
