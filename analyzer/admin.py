from django.contrib import admin
from .models import Project, AnalysisReport

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'created_at')

@admin.register(AnalysisReport)
class AnalysisReportAdmin(admin.ModelAdmin):
    list_display = ('file_name', 'project', 'pylint_score', 'analyzed_at')
