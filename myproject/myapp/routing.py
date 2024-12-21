import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .models import PingPacket, PingStatus
from datetime import datetime, timedelta

class PingPacketConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, close_code):
        pass

    async def receive(self, text_data):
        # Fetch all PingPackets and stabilize IP status
        ping_packets = PingPacket.objects.all().order_by('-timestamp')
        recent_status = {}

        for packet in ping_packets:
            ip = packet.ip_address
            if ip not in recent_status:
                recent_status[ip] = {
                    "status": packet.status,
                    "count": 1,
                    "latency": packet.delay,
                }
            else:
                if recent_status[ip]["status"] == packet.status:
                    recent_status[ip]["count"] += 1
                else:
                    recent_status[ip] = {
                        "status": packet.status,
                        "count": 1,
                        "latency": packet.delay,
                    }

        # Send updated statuses to the frontend
        data = [
            {
                "ip_address": ip,
                "status": status["status"],
                "stabilized": status["count"] > 3,  # Example: Stabilized if consistent for 3 updates
                "latency": status["latency"],
            }
            for ip, status in recent_status.items()
        ]

        await self.send(text_data=json.dumps(data))
