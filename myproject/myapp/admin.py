from django.contrib import admin
from .models import PingStatus

@admin.register(PingStatus)
class PingStatusAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'status', 'delay', 'last_updated')
from django.contrib import admin
from .models import PingPacket

@admin.register(PingPacket)
class PingPacketAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'status', 'delay', 'timestamp')
