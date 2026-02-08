import datetime
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import logging
from scapy.all import IP, TCP, sr1, conf
import asyncio
import random
import subprocess
import platform

# Variable global para servidores DNS personalizados
_custom_dns_servers = []
_use_system_dns = True  # Por defecto usa el resolver del sistema


def set_dns_servers(dns_servers_str):
    """
    Configura los servidores DNS personalizados.
    dns_servers_str: string con servidores separados por comas (ej: "8.8.8.8,1.1.1.1")
    """
    global _custom_dns_servers
    if dns_servers_str:
        _custom_dns_servers = [s.strip() for s in dns_servers_str.split(',') if s.strip()]
    else:
        _custom_dns_servers = []


def set_use_system_dns(use_system):
    """
    Configura si se debe usar el resolver DNS del sistema.
    """
    global _use_system_dns
    _use_system_dns = use_system


def resolve_with_custom_dns(hostname, dns_server, timeout=2):
    """
    Resuelve un hostname usando un servidor DNS específico con nslookup.
    Retorna una lista de IPs resueltas o lista vacía si falla.
    """
    try:
        if platform.system() == 'Windows':
            cmd = ['nslookup', hostname, dns_server]
        else:
            cmd = ['nslookup', hostname, dns_server]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = result.stdout
        
        # Parsear la salida de nslookup para extraer IPs
        ips = []
        lines = output.split('\n')
        in_answer = False
        for line in lines:
            line = line.strip()
            # Detectar inicio de la sección de respuesta
            if 'Name:' in line or 'Nombre:' in line:
                in_answer = True
                continue
            if in_answer and ('Address:' in line or 'Addresses:' in line or 'Direcci' in line):
                # Extraer IP de la línea
                parts = line.split(':')
                if len(parts) >= 2:
                    ip_part = parts[-1].strip()
                    # Validar que sea una IP válida (IPv4)
                    if all(c.isdigit() or c == '.' for c in ip_part) and ip_part.count('.') == 3:
                        ips.append(ip_part)
        return ips
    except Exception:
        return []


def resolve_hostname_all_ips(hostname, use_custom_dns=False):
    """
    Resuelve un hostname a TODAS sus direcciones IP (--resolve-all).
    Retorna una lista de IPs.
    """
    global _custom_dns_servers, _use_system_dns
    
    ips = []
    
    # Si hay servidores DNS personalizados configurados
    if _custom_dns_servers and not _use_system_dns:
        for dns_server in _custom_dns_servers:
            resolved = resolve_with_custom_dns(hostname, dns_server)
            ips.extend(resolved)
        # Eliminar duplicados manteniendo orden
        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        return unique_ips if unique_ips else []
    
    # Usar el resolver del sistema con getaddrinfo para obtener TODAS las IPs
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list(set(result[4][0] for result in results))
        return ips
    except Exception:
        # Fallback a gethostbyname_ex que también puede retornar múltiples IPs
        try:
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            return ip_list
        except Exception:
            return []


def remove_duplicate_ips(ip_list):
    """
    Elimina IPs duplicadas de una lista manteniendo el orden (--unique).
    """
    seen = set()
    unique = []
    for ip in ip_list:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique

# Importa los puertos desde los archivos de puertos comunes
from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.ports.tcp_common_ports import TCP_COMMON_PORTS
from app.logic.toolsLogic.portSscanner.scan_type.advance_scan_type.advance_widgets.ports.udp_common_ports import UDP_COMMON_PORTS

# Crea una lista de tuplas (puerto, protocolo)
# SOLO TCP
COMMON_PORTS = [(port, 'TCP') for port in TCP_COMMON_PORTS]

def scan_tcp_port(ip, port, timeout=0.05):  # Timeout más bajo
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return (port, 'open')
            elif result == 111 or result == 10061:
                return (port, 'closed')
            else:
                return (port, 'filtered')
    except Exception:
        return (port, 'filtered')

def scan_udp_port(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b'', (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                return (port, 'open')
            except socket.timeout:
                # No response: could be open|filtered
                return (port, 'open|filtered')
            except Exception:
                # ICMP unreachable: closed or filtered
                return (port, 'closed|filtered')
    except Exception:
        return (port, 'filtered')

def scan_tcp_port_syn(ip, port, timeout=0.2):  # Reducido el timeout
    """
    Escaneo SYN para detectar puertos abiertos, cerrados y filtrados usando paquetes RST.
    Requiere privilegios de administrador/root.
    """
    conf.verb = 0  # Desactiva la salida de Scapy
    pkt = IP(dst=ip)/TCP(dport=port, flags='S')
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        return (port, 'open|filtered')  # No hay respuesta, puede estar filtrado o abierto sin respuesta
    elif resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            # Enviar un RST para cerrar la conexión
            rst_pkt = IP(dst=ip)/TCP(dport=port, flags='R', seq=resp[TCP].ack, sport=resp[TCP].dport)
            sr1(rst_pkt, timeout=timeout)
            return (port, 'open')
        elif resp[TCP].flags == 0x14:  # RST-ACK
            return (port, 'closed')
    return (port, 'filtered')

def get_service_name(port, proto='tcp'):
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return 'unknown'


def get_host_info(ip_or_host, no_reverse_dns=False, reverse_dns_all=False):
    """
    Resolve an IP or hostname to an IP and optionally perform reverse DNS lookup.
    
    Parameters:
    - ip_or_host: IP address or hostname to resolve
    - no_reverse_dns: If True, skip reverse DNS (PTR) lookup entirely (-n)
    - reverse_dns_all: If True, attempt reverse DNS even for offline hosts (-R)
    
    Returns (resolved_ip, host_name) or (None, None) on failure.
    """
    global _custom_dns_servers, _use_system_dns
    
    # Resolver el hostname a IP
    try:
        if _custom_dns_servers and not _use_system_dns:
            # Usar DNS personalizado
            ips = resolve_with_custom_dns(ip_or_host, _custom_dns_servers[0])
            if ips:
                resolved_ip = ips[0]
            else:
                resolved_ip = socket.gethostbyname(ip_or_host)
        else:
            # Usar resolver del sistema
            resolved_ip = socket.gethostbyname(ip_or_host)
    except Exception:
        return (None, None)

    if no_reverse_dns:
        # Si se solicita no reverse DNS, devolvemos el IP resuelto
        # y una cadena vacía para que no se imprima nada en los logs.
        return (resolved_ip, '')

    # Realizar reverse DNS
    try:
        host_name = socket.gethostbyaddr(resolved_ip)[0]
    except Exception:
        if reverse_dns_all:
            # Con -R intentamos un lookup más agresivo
            host_name = 'No PTR (reverse DNS forzado)'
        else:
            host_name = 'No PTR'
    return (resolved_ip, host_name)

def scan_common_ports(ip, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False):
    """
    Escanea los puertos comunes de una IP y devuelve una lista de tuplas (puerto, protocolo, servicio, estado).
    Solo loguea los resultados si hay puertos abiertos.
    Ahora incluye DNS inverso por defecto.
    
    Parameters:
    - ip: IP o hostname a escanear
    - exclude_list: Lista de IPs a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    """
    if exclude_list and ip in exclude_list:
        logging.info(f'IP {ip} excluida del escaneo.')
        return []
    resolved_ip, host_name = get_host_info(ip, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all)
    if resolved_ip is None:
        logging.error(f'Failed to resolve "{ip}".')
        logging.warning('WARNING: No targets were specified, so 0 hosts scanned.')
        logging.info(f'0 IP addresses (0 hosts up) scanned in 0.00 seconds')
        return []

    port_states = []
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=1000) as executor:  # Más hilos
        futures = {executor.submit(scan_tcp_port, resolved_ip, port): (port, proto) for port, proto in COMMON_PORTS}
        for future in as_completed(futures):
            port, proto = futures[future]
            port_num, state = future.result()
            service = get_service_name(port_num, proto.lower())
            port_states.append((port, proto, service, state))
    open_ports = [(port, proto, service) for port, proto, service, state in port_states if state == 'open']
    now = datetime.now().astimezone()
    fecha_hora = now.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    logging.info(f"\n========== Escaneando IP: {ip} ({host_name}) ==========")
    logging.info(f"Escaneo realizado el: {fecha_hora}")
    # Mostrar si existe DNS inverso (PTR)
    # Si existe un host_name válido (no vacío), lo mostramos.
    if host_name:
        if host_name != 'No PTR':
            logging.info(f"Reverse DNS: {host_name}")
        else:
            logging.info("Reverse DNS: No PTR (sin registro)")
    # Si host_name es cadena vacía significa que el reverse DNS fue omitido
    # y por tanto no imprimimos nada relativo a PTR.
    scan_label = f"Escaneando {ip}" + (f" ({host_name})" if host_name else "")
    logging.info(f"{scan_label} en busca de puertos comunes abiertos...")
    for port, proto, service in open_ports:
        logging.info(f"Puerto {port}/{proto} ({service}): open")
    elapsed = time.time() - start_time
    logging.info(f"Escaneo finalizado en {elapsed:.2f} segundos.")
    return port_states

async def async_scan_tcp_port(ip, port, timeout=10):
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return (port, 'open')
    except asyncio.TimeoutError:
        # Si hay timeout, puede estar filtrado o abierto sin respuesta
        return (port, 'open|filtered')
    except ConnectionRefusedError:
        return (port, 'closed')
    except Exception:
        return (port, 'filtered')

async def async_scan_common_ports(ip, no_reverse_dns=False, reverse_dns_all=False):
    """
    Escanea los puertos comunes de una IP de forma asíncrona.
    
    Parameters:
    - ip: IP o hostname a escanear
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    """
    try:
        resolved_ip, host_name = get_host_info(ip, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all)
        if resolved_ip is None:
            logging.error(f'Failed to resolve "{ip}".')
            logging.warning('WARNING: No targets were specified, so 0 hosts scanned.')
            logging.info(f'0 IP addresses (0 hosts up) scanned in 0.00 seconds')
            return []
    except Exception:
        logging.error(f'Failed to resolve "{ip}".')
        logging.warning('WARNING: No targets were specified, so 0 hosts scanned.')
        logging.info(f'0 IP addresses (0 hosts up) scanned in 0.00 seconds')
        return []

    port_states = []
    start_time = time.time()
    tasks = [async_scan_tcp_port(resolved_ip, port) for port, _ in COMMON_PORTS]
    results = await asyncio.gather(*tasks)
    for (port, proto), (port_num, state) in zip(COMMON_PORTS, results):
        service = get_service_name(port_num, proto.lower())
        port_states.append((port, proto, service, state))
    open_ports = [(port, proto, service) for port, proto, service, state in port_states if state == 'open']
    now = datetime.now().astimezone()
    fecha_hora = now.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    title = f"\n========== Escaneando IP: {ip}" + (f" ({host_name})" if host_name else "") + " =========="
    logging.info(title)
    logging.info(f"Escaneo realizado el: {fecha_hora}")
    if host_name:
        if host_name != 'No PTR':
            logging.info(f"Reverse DNS: {host_name}")
        else:
            logging.info("Reverse DNS: No PTR (sin registro)")
    # Si host_name es cadena vacía, el reverse DNS fue omitido: no imprimimos nada
    scan_label = f"Escaneando {ip}" + (f" ({host_name})" if host_name else "")
    logging.info(f"{scan_label} en busca de puertos comunes abiertos...")
    for port, proto, service in open_ports:
        logging.info(f"Puerto {port}/{proto} ({service}): open")
    elapsed = time.time() - start_time
    logging.info(f"Escaneo finalizado en {elapsed:.2f} segundos.")
    return port_states

def scan_multiple_ips(ip_list, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False, unique=False):
    """
    Escanea múltiples IPs.
    
    Parameters:
    - ip_list: Lista de IPs a escanear
    - exclude_list: Lista de IPs a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    - unique: Eliminar IPs duplicadas (--unique)
    """
    if exclude_list:
        ip_list = exclude_ips(ip_list, exclude_list)
    
    # Aplicar --unique si está habilitado
    if unique:
        ip_list = remove_duplicate_ips(ip_list)
    
    results = {}
    for ip in ip_list:
        port_states = scan_common_ports(ip, exclude_list=exclude_list, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all)
        results[ip] = port_states
    logging.info("Análisis de múltiples IPs finalizado.")
    return results

def ip_to_int(ip):
    return sum(int(part) << (8 * (3 - i)) for i, part in enumerate(ip.split('.')))

def int_to_ip(num):
    return '.'.join(str((num >> (8 * (3 - i))) & 0xFF) for i in range(4))

def scan_ip_range(start_ip, end_ip, exclude_list=None):
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    ip_list = [int_to_ip(ip_int) for ip_int in range(start, end + 1)]
    if exclude_list:
        ip_list = exclude_ips(ip_list, exclude_list)
    return scan_multiple_ips(ip_list)

def scan_multiple_ip_ranges(ranges_str, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False, unique=False):
    """
    Escanea múltiples rangos de IPs.
    
    Parameters:
    - ranges_str: String con rangos de IPs (ej: "192.168.1.100-120,192.168.1.200-210")
    - exclude_list: Lista de IPs a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    - unique: Eliminar IPs duplicadas (--unique)
    """
    results = {}
    ranges = [r.strip() for r in ranges_str.split(',') if r.strip()]
    ip_list = []
    for r in ranges:
        if '-' not in r:
            continue
        base, end = r.split('-')
        base_parts = base.strip().split('.')
        if len(base_parts) != 4:
            continue
        try:
            start_ip = '.'.join(base_parts[:3] + [str(int(base_parts[3]))])
            start = int(base_parts[3])
            end = int(end.strip())
            if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
                continue
            for last_octet in range(start, end + 1):
                ip = '.'.join(base_parts[:3] + [str(last_octet)])
                ip_list.append(ip)
        except Exception:
            continue

    if exclude_list:
        ip_list = exclude_ips(ip_list, exclude_list)
    
    # Aplicar --unique si está habilitado
    if unique:
        ip_list = remove_duplicate_ips(ip_list)

    if not ip_list:
        return results

    # Paraleliza el escaneo por IP (cada IP ejecuta scan_common_ports)
    max_workers = min(200, max(10, len(ip_list)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_common_ports, ip, exclude_list, no_reverse_dns, reverse_dns_all): ip for ip in ip_list}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                logging.error(f"Error escaneando {ip}: {e}")
                results[ip] = []
    logging.info("Análisis de múltiples rangos IP finalizado.")
    return results

def scan_cidr(cidr_str, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False, unique=False):
    """
    Escanea un rango CIDR.
    
    Parameters:
    - cidr_str: Notación CIDR (ej: "192.168.1.0/24")
    - exclude_list: Lista de IPs a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    - unique: Eliminar IPs duplicadas (--unique)
    """
    results = {}
    try:
        ip_part, prefix = cidr_str.split('/')
        prefix = int(prefix)
        if not (24 <= prefix <= 32):
            logging.error("El prefijo debe estar entre /24 y /32.")
            logging.info(f"Análisis de CIDR {cidr_str} finalizado.")
            return results

        start_ip_int = ip_to_int(ip_part.strip())
        num_hosts = 2 ** (32 - prefix)
        end_ip_int = start_ip_int + num_hosts - 1

        ip_list = [int_to_ip(ip_int) for ip_int in range(start_ip_int, end_ip_int + 1)]
        if exclude_list:
            ip_list = exclude_ips(ip_list, exclude_list)
        res = scan_multiple_ips(ip_list, exclude_list=exclude_list, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all, unique=unique)
        logging.info(f"Análisis de CIDR {cidr_str} finalizado.")
        return res
    except Exception as e:
        logging.error(f"Formato CIDR inválido o error: {e}")
        logging.info(f"Análisis de CIDR {cidr_str} finalizado.")
        return results

async def scan_domain(domain, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False, resolve_all=False):
    """
    Escanea los puertos comunes de un dominio (ej: 'google.com') en paralelo usando escaneo TCP asíncrono.
    Devuelve la lista de puertos y sus estados (open, closed, open|filtered).
    Si el dominio o su IP está en exclude_list, no se escanea.
    
    Parameters:
    - domain: Dominio a escanear
    - exclude_list: Lista de IPs/dominios a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    - resolve_all: Escanear TODAS las IPs a las que resuelve el dominio (--resolve-all)
    """
    all_results = []
    
    # Si resolve_all está habilitado, obtener todas las IPs del dominio
    if resolve_all:
        all_ips = resolve_hostname_all_ips(domain)
        if not all_ips:
            logging.error(f"No se pudo resolver el dominio '{domain}'.")
            logging.info(f"Análisis de dominio {domain} finalizado.")
            return []
        
        logging.info(f"Dominio '{domain}' resuelto a {len(all_ips)} direcciones IP: {', '.join(all_ips)}")
        
        for ip in all_ips:
            if exclude_list and (domain in exclude_list or ip in exclude_list):
                logging.info(f"IP {ip} del dominio '{domain}' excluida del escaneo.")
                continue
            
            now = datetime.now().astimezone()
            fecha_hora = now.strftime("%Y-%m-%d %H:%M:%S %Z%z")
            logging.info(f"\n========== Escaneando dominio: {domain} ({ip}) ==========")
            logging.info(f"Escaneo realizado el: {fecha_hora}")
            
            start_time = time.time()
            tasks = [async_scan_tcp_port(ip, port) for port, _ in COMMON_PORTS]
            try:
                results = await asyncio.gather(*tasks)
                port_states = []
                for (port, proto), (port_num, state) in zip(COMMON_PORTS, results):
                    service = get_service_name(port_num, proto.lower())
                    port_states.append((port, proto, service, state))
                    if state in ('open', 'closed'):
                        logging.info(f"Puerto {port}/{proto} ({service}): {state}")
                all_results.extend(port_states)
                elapsed = time.time() - start_time
                logging.info(f"Escaneo de {ip} finalizado en {elapsed:.2f} segundos.")
            except Exception as e:
                logging.error(f"Error escaneando IP {ip}: {e}")
        
        logging.info(f"Análisis de dominio {domain} finalizado.")
        return all_results
    
    # Comportamiento normal (una sola IP)
    resolved_ip, host_name = get_host_info(domain, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all)
    if resolved_ip is None:
        logging.error(f"No se pudo resolver el dominio '{domain}'.")
        logging.info(f"Análisis de dominio {domain} finalizado.")
        return []
    ip = resolved_ip
    # Excluir por dominio o por IP resuelta
    if exclude_list and (domain in exclude_list or ip in exclude_list):
        logging.info(f"Dominio '{domain}' ({ip}) excluido del escaneo.")
        logging.info(f"Análisis de dominio {domain} finalizado.")
        return []
    now = datetime.now().astimezone()
    fecha_hora = now.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    logging.info(f"\n========== Escaneando dominio: {domain} ==========")
    logging.info(f"Escaneo realizado el: {fecha_hora}")
    logging.info(f"Dominio '{domain}' resuelto a IP: {ip}")
    logging.info(f"Escaneando {domain} en busca de puertos comunes abiertos/cerrados...")
    start_time = time.time()
    tasks = [async_scan_tcp_port(ip, port) for port, _ in COMMON_PORTS]
    try:
        results = await asyncio.gather(*tasks)
        port_states = []
        for (port, proto), (port_num, state) in zip(COMMON_PORTS, results):
            service = get_service_name(port_num, proto.lower())
            port_states.append((port, proto, service, state))
            if state in ('open', 'closed'):
                logging.info(f"Puerto {port}/{proto} ({service}): {state}")
        elapsed = time.time() - start_time
        logging.info(f"Escaneo finalizado en {elapsed:.2f} segundos.")
        logging.info(f"Análisis de dominio {domain} finalizado.")
        return port_states
    except Exception as e:
        logging.error(f"Error escaneando dominio '{domain}': {e}")
        logging.info(f"Análisis de dominio {domain} finalizado.")
        return []

def scan_targets_from_file(file_path, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False, resolve_all=False, unique=False):
    """
    Lee un archivo con una lista de objetivos (IP, rango, CIDR, dominio) y los escanea uno por uno.
    El escaneo de dominios se realiza exactamente igual que scan_domain (con logging detallado).
    Al finalizar, avisa en el log que el escaneo de todos los objetivos ha terminado.
    
    Parameters:
    - file_path: Ruta al archivo con objetivos
    - exclude_list: Lista de IPs/dominios a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    - resolve_all: Escanear TODAS las IPs de cada dominio (--resolve-all)
    - unique: Eliminar IPs duplicadas (--unique)
    """
    results = {}
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        for target in lines:
            if '/' in target:  # CIDR
                results[target] = scan_cidr(target, exclude_list, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all, unique=unique)
            elif '-' in target:  # Rango de IPs
                results[target] = scan_multiple_ip_ranges(target, exclude_list, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all, unique=unique)
            elif all(c.isdigit() or c == '.' for c in target):  # IP individual
                if exclude_list and target in exclude_list:
                    continue
                results[target] = scan_common_ports(target, exclude_list=exclude_list, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all)
            else:
                # Dominio: excluir por nombre o IP resuelta
                try:
                    ip = socket.gethostbyname(target)
                except Exception:
                    ip = None
                if exclude_list and (target in exclude_list or (ip and ip in exclude_list)):
                    logging.info(f"Dominio '{target}' ({ip}) excluido del escaneo.")
                    logging.info(f"Análisis de dominio {target} finalizado.")
                    continue
                results[target] = asyncio.run(scan_domain(target, exclude_list=exclude_list, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all, resolve_all=resolve_all))
        logging.info("Escaneo de todos los objetivos del archivo finalizado.")
    except Exception as e:
        logging.error(f"Error al procesar el archivo de objetivos: {e}")
        logging.info("Análisis de archivo de objetivos finalizado.")
    return results

def generate_random_ip():
    # Evita rangos privados y reservados
    while True:
        ip = "{}.{}.{}.{}".format(
            random.randint(1, 223),  # 1-223 (evita 0, 224+)
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(1, 254)   # evita .0 y .255
        )
        # Excluye rangos privados y reservados
        first = int(ip.split('.')[0])
        second = int(ip.split('.')[1])
        if first == 10 or (first == 192 and second == 168) or (first == 172 and 16 <= second <= 31):
            continue
        if first == 127 or first == 0 or first >= 224:
            continue
        return ip

def scan_random_ips(n=10, exclude_list=None, no_reverse_dns=False, reverse_dns_all=False):
    """
    Escanea n IPs aleatorias.
    
    Parameters:
    - n: Número de IPs aleatorias a escanear
    - exclude_list: Lista de IPs a excluir
    - no_reverse_dns: No realizar reverse DNS (-n)
    - reverse_dns_all: Realizar reverse DNS incluso para hosts offline (-R)
    """
    results = {}
    scanned = set()
    start_time = time.time()
    count = 0
    while count < n:
        ip = generate_random_ip()
        while ip in scanned or (exclude_list and ip in exclude_list):
            ip = generate_random_ip()
        scanned.add(ip)
        logging.info(f"Escaneando IP aleatoria: {ip}")
        port_states = scan_common_ports(ip, no_reverse_dns=no_reverse_dns, reverse_dns_all=reverse_dns_all)
        abiertos = [p for p in port_states if p[3] == 'open']
        cerrados = [p for p in port_states if p[3] == 'closed']
        if abiertos or cerrados:
            for port, proto, service, state in abiertos:
                logging.info(f"Puerto {port}/{proto} ({service}): open")
            for port, proto, service, state in cerrados:
                logging.info(f"Puerto {port}/{proto} ({service}): closed")
        results[ip] = port_states
        count += 1
    elapsed = time.time() - start_time
    logging.info(f"Escaneo de {n} IPs aleatorias finalizado en {elapsed:.2f} segundos.")
    return {"results": results, "elapsed": elapsed}

def exclude_ips(ip_list, exclude_list):
    """
    Excluye las IPs presentes en exclude_list del ip_list.
    """
    exclude_set = set(exclude_list)
    return [ip for ip in ip_list if ip not in exclude_set]

def get_exclude_list(self):
    exclude_list = []
    # Excluir IPs manuales
    if self.checkbox_exclude.isChecked():
        val = self.input_exclude.text().strip()
        if val:
            exclude_list += [ip.strip() for ip in val.replace(',', ' ').split() if ip.strip()]
    # Excluir desde archivo
    if self.checkbox_excludefile.isChecked():
        file_path = self.input_excludefile.text().strip()
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    exclude_list += [line.strip() for line in f if line.strip()]
            except Exception:
                pass  # Puedes emitir un mensaje si quieres
    return exclude_list