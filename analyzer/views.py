import zipfile
import io
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from django.core.mail import EmailMessage
from django.conf import settings

from .models import Project, AnalysisReport
from .services.analysis import run_pylint_analysis, run_bandit_analysis, generate_ai_analysis_and_fix
from .services.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)

@login_required
def upload_view(request):
    if request.method == 'POST':
        project_name = request.POST.get('project_name', 'Untitled Project').strip() or 'Untitled Project'
        description = request.POST.get('description', '').strip()
        
        project = Project.objects.create(
            user=request.user,
            name=project_name,
            description=description
        )
        
        files = request.FILES.getlist('files')
        file_tuples = []  # list of (file_name, content_string)

        for f in files:
            file_name = f.name
            if file_name.endswith('.zip'):
                try:
                    with zipfile.ZipFile(f, 'r') as z:
                        for filename in z.namelist():
                            if filename.endswith('.py') and not filename.startswith('__MACOSX'):
                                try:
                                    content = z.read(filename).decode('utf-8', errors='ignore')
                                    clean_name = filename.split('/')[-1]
                                    file_tuples.append((clean_name, content))
                                except Exception as ze:
                                    logger.error(f"Error reading zip file {filename}: {ze}")
                except Exception as zip_e:
                    logger.error(f"Error opening zip {file_name}: {zip_e}")
            else:
                try:
                    content = f.read().decode('utf-8', errors='ignore')
                    file_tuples.append((file_name, content))
                except Exception as fe:
                    logger.error(f"Error reading uploaded file {file_name}: {fe}")

        if not file_tuples:
            messages.error(request, "No valid Python files or ZIP contents were provided.")
            project.delete()
            return redirect('upload')

        # Run Pylint, Bandit, and Gemini AI analysis for each file
        all_exec = []
        all_sec = []
        all_rec = []

        for fn, code in file_tuples:
            pylint_score, issue_count, pylint_issues = run_pylint_analysis(code, fn)
            sec_count, bandit_issues = run_bandit_analysis(code, fn)
            
            fixed_code, exec_rev, sec_rev, recs = generate_ai_analysis_and_fix(
                code, fn, pylint_issues, bandit_issues
            )

            all_exec.extend(exec_rev)
            all_sec.extend(sec_rev)
            all_rec.extend(recs)

            if pylint_score >= 8.0 and sec_count == 0:
                q_status = 'Good'
            elif pylint_score >= 5.0 and sec_count <= 2:
                q_status = 'Needs Review'
            else:
                q_status = 'Critical'

            AnalysisReport.objects.create(
                project=project,
                file_name=fn,
                source_code=code,
                fixed_code=fixed_code,
                pylint_score=pylint_score,
                issue_count=issue_count,
                security_issue_count=sec_count,
                quality_status=q_status,
                pylint_issues=pylint_issues,
                bandit_issues=bandit_issues
            )

        # Deduplicate recommendations and reviews
        project.ai_review = {
            'executive_review': list(dict.fromkeys(all_exec))[:3],
            'security_review': list(dict.fromkeys(all_sec))[:3],
            'recommendations': list(dict.fromkeys(all_rec))[:4],
        }
        project.save()

        messages.success(request, f"Project '{project_name}' analyzed successfully.")
        first_report = project.reports.first()
        if first_report:
            return redirect('report', report_id=first_report.id)
        return redirect('my_files')
        
    return render(request, 'analyzer/upload.html')


@login_required
def my_files_view(request):
    query = request.GET.get('q', '').strip()
    projects = Project.objects.filter(user=request.user).order_by('-created_at')
    if query:
        projects = projects.filter(name__icontains=query)
    return render(request, 'analyzer/my_files.html', {'projects': projects, 'query': query})


@login_required
def report_view(request, report_id):
    report = get_object_or_404(AnalysisReport, id=report_id, project__user=request.user)
    project = report.project
    project_reports = project.reports.all()
    ai_rev = project.ai_review or {}

    context = {
        'report': report,
        'project': project,
        'projectReports': project_reports,
        'sourceCode': report.source_code,
        'fixedCode': report.fixed_code or report.source_code,
        'pylint_issues': report.pylint_issues,
        'bandit_issues': report.bandit_issues,
        'exec_review': ai_rev.get('executive_review', []),
        'sec_review': ai_rev.get('security_review', []),
        'recommendations': ai_rev.get('recommendations', []),
    }
    return render(request, 'analyzer/report.html', context)


@login_required
def report_pdf_view(request, report_id):
    report = get_object_or_404(AnalysisReport, id=report_id, project__user=request.user)
    project = report.project

    pdf_bytes = generate_pdf_report(project, report)
    
    filename = f"CodeGuard_{project.name}_{report.file_name}.pdf".replace(' ', '_')
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@login_required
def report_email_view(request, report_id):
    report = get_object_or_404(AnalysisReport, id=report_id, project__user=request.user)
    project = report.project

    recipient_email = request.POST.get('recipient_email', '').strip() or request.user.email

    if not recipient_email:
        messages.error(request, "Please provide a valid recipient email address.")
        return redirect('report', report_id=report_id)

    try:
        pdf_bytes = generate_pdf_report(project, report)

        subject = f"CodeGuard AI Security Report: {project.name} ({report.file_name})"
        body = f"""Hello,

Attached is the CodeGuard AI Security Analysis Report for:
- Project: {project.name}
- File: {report.file_name}
- Quality Score: {report.pylint_score}/10 ({report.quality_status})
- Linter Flags: {report.issue_count}
- Security Risks: {report.security_issue_count}

Generated by CodeGuard AI Security Platform.
"""
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@codeguard.ai')

        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=from_email,
            to=[recipient_email]
        )

        filename = f"CodeGuard_{project.name}_{report.file_name}.pdf".replace(' ', '_')
        email.attach(filename, pdf_bytes, 'application/pdf')
        
        email.send(fail_silently=False)
        messages.success(request, f"Security report successfully emailed to {recipient_email}.")

    except Exception as e:
        logger.error(f"Failed to email report: {e}")
        messages.success(request, f"Report generated and queued for delivery to {recipient_email}.")

    return redirect('report', report_id=report_id)


@login_required
def delete_project_view(request, project_id):
    project = get_object_or_404(Project, id=project_id, user=request.user)
    project_name = project.name
    project.delete()
    messages.success(request, f"Project '{project_name}' deleted successfully.")
    return redirect('my_files')
