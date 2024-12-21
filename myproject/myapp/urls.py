from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),  # Make login the main URL
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('add_item/', views.add_item_view, name='add_item'),
    path('view_items/', views.view_items_view, name='view_items'),
    path('modify_item/<int:item_index>/', views.modify_item_view, name='modify_item'),
    path('delete_item/<int:item_index>/', views.delete_item_view, name='delete_item'),
    path('add_user/', views.add_user_view, name='add_user'),
    path('modify_user/', views.modify_user_view, name='modify_user'),
    path('modify_user/<int:user_index>/', views.modify_user_view, name='modify_user_specific'),
    path('remove_user/<int:user_index>/', views.remove_user_view, name='remove_user'),
    path('view_tickets/', views.view_tickets_view, name='view_tickets'),
    path('edit_user_privileges/<int:user_index>/', views.edit_user_privileges_view, name='edit_user_privileges'),
    path('logout/', views.logout_view, name='logout_view'),
    path('notes/', views.notes_view, name='notes'),
    path('subnet_calculator/', views.subnet_calculator_view, name='subnet_calculator'),
    path('purchase_request/', views.purchase_request_view, name='purchase_request'),
    path('api/update_ping_status/', views.update_ping_status, name='update_ping_status'),
    path('ping_packets/', views.ping_packets_view, name='ping_packets'),
    path('ping_history/<str:ip_address>/', views.ping_history_view, name='ping_history'),
    # HTML rendering views
    path('manage-ips/', views.manage_ips_view, name='manage_ips'),
    # JSON API views
    path('api/ping_packets/', views.ping_packets_json, name='ping_packets_json'),
    path('api/ping_history/<str:ip_address>/', views.ping_history_json, name='ping_history_json'),
    path('manage-urls/', views.manage_urls_view, name='manage_urls'),  # Main page for managing URLs
    path('manage-urls/edit/<int:url_index>/', views.edit_url_view, name='edit_url'),
    path('scan_ip/', views.scan_ip_view, name='scan_ip'),  # Add a new URL route for scanning IPs
    path('gym-management/', views.gym_management_view, name='gym_management'),
    path('case_calendar_view', views.case_calendar_view, name='case_calendar'),
    path('manage_cases/', views.manage_cases_view, name='manage_cases'),
    path('manage_code_snippets/', views.manage_code_snippets_view, name='manage_code_snippets'),
    path('edit_code_snippet/<int:snippet_index>/', views.edit_code_snippet_view, name='edit_code_snippet'),

]
# Page for editing a specific URL





