from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock
import netifaces
from classifier import discover_and_classify

class EchoDotApp(App):
    def build(self):
        self.device_list = BoxLayout(orientation='vertical', spacing=5)
        Clock.schedule_interval(self.update_devices, 30)  # update every 30s
        return self.device_list

    def get_local_subnet(self):
        """Attempt to autodetect subnet, fallback if necessary"""
        try:
            gws = netifaces.gateways()
            default_iface = gws['default'][netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
            ip = addrs['addr']
            netmask = addrs['netmask']

            # Convert netmask to CIDR
            mask_parts = [int(x) for x in netmask.split('.')]
            bits = sum(bin(part).count('1') for part in mask_parts)
            return f"{ip}/{bits}"
        except Exception:
            # Fallback if autodetect fails
            return "192.168.1.0/24"

    def update_devices(self, *args):
        subnet = self.get_local_subnet()
        self.devices = discover_and_classify(subnet)  # uses cache & confidence
        self.device_list.clear_widgets()
        for d in self.devices:
            entry = f"{d['ip']} | {d['classification']} | Confidence: {d['confidence']}%"
            self.device_list.add_widget(Label(text=entry))

if __name__ == "__main__":
    EchoDotApp().run()
