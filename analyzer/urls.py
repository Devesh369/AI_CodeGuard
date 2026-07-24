from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_view, name='upload'),
    path('files/', views.my_files_view, name='my_files'),
    path('report/<int:report_id>/', views.report_view, name='report'),
    path('report/<int:report_id>/pdf/', views.report_pdf_view, name='report_pdf'),
    path('report/<int:report_id>/email/', views.report_email_view, name='report_email'),
    path('delete_project/<int:project_id>/', views.delete_project_view, name='delete_project'),
]
