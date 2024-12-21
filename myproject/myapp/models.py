from django.db import models

class PingStatus(models.Model):
    ip_address = models.CharField(max_length=45, unique=True)
    status = models.CharField(max_length=10)
    delay = models.FloatField(null=True, blank=True)  # Make sure this field can accept null values if necessary
    last_updated = models.DateTimeField(auto_now=True)  # Automatically update the timestamp when saving

    def __str__(self):
        return f"Ping to {self.ip_address} - Status: {self.status} - Last Updated: {self.last_updated}"



class PingPacket(models.Model):
    ip_address = models.CharField(max_length=45)
    status = models.CharField(max_length=10)
    delay = models.FloatField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Ping to {self.ip_address} at {self.timestamp} - Status: {self.status}"
