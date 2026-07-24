from django.db import models
from django.contrib.auth.models import User

class Project(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='projects')
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    ai_review = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    @property
    def avg_score(self):
        reports = self.reports.all()
        if not reports.exists():
            return 10.0
        total = sum(r.pylint_score for r in reports)
        return round(total / reports.count(), 1)

    @property
    def total_issues(self):
        reports = self.reports.all()
        return sum(r.issue_count for r in reports)

    @property
    def total_security_issues(self):
        reports = self.reports.all()
        return sum(r.security_issue_count for r in reports)

    @property
    def overall_status(self):
        score = self.avg_score
        if score >= 8.0:
            return "Good"
        elif score >= 5.0:
            return "Needs Review"
        return "Critical"

class AnalysisReport(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='reports')
    file_name = models.CharField(max_length=255)
    source_code = models.TextField()
    fixed_code = models.TextField(blank=True, null=True)
    pylint_score = models.FloatField(default=0.0)
    issue_count = models.IntegerField(default=0)
    security_issue_count = models.IntegerField(default=0)
    quality_status = models.CharField(max_length=50, default='Good')
    pylint_issues = models.JSONField(default=list)
    bandit_issues = models.JSONField(default=list)
    analyzed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file_name} - {self.pylint_score}"
