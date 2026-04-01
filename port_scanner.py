#!/usr/bin/env python3
import asyncio
import argparse
import socket
import ssl
import json
import csv
import sys
from typing import List, Tuple, AsyncGenerator, Any

# Improve Windows compatibility for asyncio
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def _probe_for_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int, target: str) -> str:
    """Send probes to elicit banners from common services."""
    try:
        if port in (80, 8080, 8000):
            # HTTP probe
            msg = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
            writer.write(msg)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode(errors='ignore').strip()
        
        if port in (25, 587):
            # SMTP - wait for greeting then send EHLO
            # Some servers send greeting immediately
            try:
                # wait slightly for initial banner
                initial = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if initial:
                    return initial.decode(errors='ignore').strip()
            except asyncio.TimeoutError:
                pass
            
            writer.write(b"EHLO example.com\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode(errors='ignore').strip()

        if port == 21:
            # FTP usually sends banner on connect
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode(errors='ignore').strip()
            
    except Exception:
        pass
    return ""


async def scan_port_async(target: str, port: int, timeout: float, service_probe: bool = True) -> Tuple[int, bool, str, str]:
    """
    Scans a single port.
    Returns: (port, is_open, service, banner)
    """
    conn_fut = asyncio.open_connection(target, port)
    try:
        reader, writer = await asyncio.wait_for(conn_fut, timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False, "closed", ""

    # Port is open
    banner = ""
    service = "unknown"
    
    try:
        if service_probe:
            # Try to read initial banner first (some services send immediately like SSH, FTP, SMTP)
            try:
                # Quick read with short timeout for spontaneous banners
                initial_data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                if initial_data:
                    banner = initial_data.decode(errors='ignore').strip()
            except asyncio.TimeoutError:
                pass

            # If no banner, try to probe or handle specific ports
            if not banner:
                banner = await _probe_for_banner(reader, writer, port, target)
            
            # If still no banner and port 443, try SSL
            if not banner and port == 443:
                 # Simple heuristic for now, better full SSL handshake would require a separate connection
                 service = "https"
                 banner = "TLS/SSL Service"

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    # Basic service detection
    service = detect_service(port, banner)
    return port, True, service, banner


def detect_service(port: int, banner: str) -> str:
    b = (banner or '').lower()
    if 'ssh-' in b or port == 22:
        return 'ssh'
    if b.startswith('http/') or 'server:' in b or 'http' in b or port in (80, 8080, 8000):
        return 'http'
    if 'smtp' in b or port in (25, 587):
        return 'smtp'
    if 'ftp' in b or port == 21:
        return 'ftp'
    if 'pop3' in b or port == 110:
        return 'pop3'
    if 'imap' in b or port == 143:
        return 'imap'
    if b.startswith('tls') or port == 443:
        return 'https'
    if b:
        return 'unknown'
    return 'unknown'  # Default if open but no identification


def parse_ports(port_str: str) -> List[int]:
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a, b = map(int, part.split('-', 1))
                ports.update(range(a, b + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 0 < p < 65536)


async def scan_generator(target: str, ports: List[int], concurrency: int, timeout: float, service_probe: bool) -> AsyncGenerator[Tuple[int, bool, str, str], None]:
    """
    Async generator that yields results as they are found.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_scan(p):
        async with semaphore:
            return await scan_port_async(target, p, timeout, service_probe)

    # Create all tasks
    tasks = [asyncio.create_task(sem_scan(p)) for p in ports]
    
    # As each task completes, yield it
    for future in asyncio.as_completed(tasks):
        result = await future
        yield result


def scan_generator_sync(target: str, ports: str = '1-1024', threads: int = 100, timeout: float = 1.0, service: bool = True):
    """
    Synchronous generator for Flask or other sync apps to consume results in real-time.
    """
    import queue
    import threading
    
    # Resolve first
    try:
        resolved = socket.gethostbyname(target)
    except Exception:
        return

    port_list = parse_ports(ports)
    q = queue.Queue()
    
    # Sentinel for end of stream
    SENTINEL = object()

    def runner():
        async def async_wrapper():
            async for item in scan_generator(resolved, port_list, threads, timeout, service):
                q.put(item)
        
        try:
            asyncio.run(async_wrapper())
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error in scan runner: {e}", file=sys.stderr)
            pass
        finally:
            q.put(SENTINEL)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    
    while True:
        item = q.get()
        if item is SENTINEL:
            break
        yield item


def scan_target(target: str, ports: str = '1-1024', threads: int = 100, timeout: float = 1.0, service: bool = True, verbose: bool = False) -> List[Tuple[int, str, str]]:
    """
    Legacy wrapper for synchronous usage.
    Returns: list of (port, service, banner)
    """
    try:
        # Resolve first
        resolved = socket.gethostbyname(target)
    except Exception:
        return []

    port_list = parse_ports(ports)
    
    async def run_scan():
        results = []
        async for port, is_open, svc, banner in scan_generator(resolved, port_list, threads, timeout, service):
            if is_open:
                results.append((port, svc, banner))
                if verbose:
                    print(f"[+] Port {port}/tcp open ({svc})")
            elif verbose:
                # Optional: print closed ports in verbose
                pass
        return sorted(results)

    return asyncio.run(run_scan())


def main():
    parser = argparse.ArgumentParser(description='Async Port Scanner')
    parser.add_argument('target', help='Target hostname or IP')
    parser.add_argument('-p', '--ports', default='1-1024')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Concurrency text (formerly threads)', dest='concurrency')
    parser.add_argument('--timeout', type=float, default=1.0)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--service', action='store_true', default=True)
    parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text')
    parser.add_argument('--output')
    args = parser.parse_args()

    results = scan_target(args.target, args.ports, args.concurrency, args.timeout, args.service, args.verbose)
    
    if args.format == 'text':
        # Results already printed if verbose, but let's print summary if not verbose or just ensure output
        if not args.verbose:
            for p, s, b in results:
                print(f"Port {p}/tcp open ({s}) - {b}")
    else:
        # Write output
        data = [{"target": args.target, "port": p, "service": s, "banner": b} for p, s, b in results]
        if args.output:
            if args.format == 'json':
                with open(args.output, 'w') as f:
                    json.dump(data, f, indent=2)
            elif args.format == 'csv':
                with open(args.output, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['target', 'port', 'service', 'banner'])
                    writer.writeheader()
                    writer.writerows(data)
            print(f"Wrote {len(results)} results to {args.output}")
        else:
            if args.format == 'json':
                print(json.dumps(data, indent=2))

if __name__ == '__main__':
    main()
