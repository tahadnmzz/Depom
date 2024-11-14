import nmap

def scan_network(network):
    # Nmap tarayıcısını başlat
    nm = nmap.PortScanner()
    
    print(f"{network} adres aralığında tarama başlatılıyor...")
    
    # Ağ taraması yapılır
    nm.scan(hosts=network, arguments='-sn')  # -sn sadece aktif cihazları bulur
    
    # Tarama sonuçlarını yazdır
    print("Ağdaki aktif cihazlar:")
    for host in nm.all_hosts():
        if 'hostnames' in nm[host]:
            print(f"IP Adresi: {host}, Host Adı: {nm[host].hostname()}")
        else:
            print(f"IP Adresi: {host}, Host Adı: Bilinmiyor")

# Ağ aralığınızı belirleyin, örneğin 192.168.1.0/24
network = '192.168.1.0/24'
scan_network(network)
