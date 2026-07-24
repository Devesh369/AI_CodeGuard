from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import UserRegistrationForm
from analyzer.models import Project, AnalysisReport

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'accounts/login.html')

def register_view(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            login(request, user)
            return redirect('dashboard')
        else:
            for error in form.non_field_errors():
                messages.error(request, error)
    else:
        form = UserRegistrationForm()
    return render(request, 'accounts/register.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('/login/?logout=true')

@login_required
def dashboard_view(request):
    projects = Project.objects.filter(user=request.user)
    reports = AnalysisReport.objects.filter(project__user=request.user)
    
    total_projects = projects.count()
    total_files = reports.count()
    
    total_issues = sum(r.issue_count for r in reports) if reports else 0
    security_count = sum(r.security_issue_count for r in reports) if reports else 0
    avg_score = round(sum(r.pylint_score for r in reports) / total_files, 1) if total_files > 0 else 0.0

    recent_projects = projects.order_by('-created_at')[:5]
    recent_reports = reports.order_by('-analyzed_at')[:5]

    context = {
        'total_projects': total_projects,
        'total_files': total_files,
        'average_score': avg_score,
        'total_code_issues': total_issues,
        'security_count': security_count,
        'recentProjects': recent_projects,
        'recent': recent_reports,
        'excellent': sum(1 for r in reports if r.pylint_score >= 9),
        'good': sum(1 for r in reports if 7 <= r.pylint_score < 9),
        'improve': sum(1 for r in reports if 4 <= r.pylint_score < 7),
        'poor': sum(1 for r in reports if r.pylint_score < 4),
    }
    return render(request, 'accounts/dashboard.html', context)
