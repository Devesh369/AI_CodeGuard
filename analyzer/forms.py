from django import forms
from .models import Project

class ProjectUploadForm(forms.ModelForm):
    zip_file = forms.FileField(required=False)
    
    class Meta:
        model = Project
        fields = ['name', 'description']
