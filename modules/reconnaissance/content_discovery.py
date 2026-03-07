import os
import json
from core.utils import run_command, save_raw_output

def discover_content(domain, workspace_dir, wordlist=None, timeout=300, cookies_file=None):
    print("[*] Menjalankan content discovery dengan ffuf...")

    if wordlist is None or not os.path.exists(wordlist):
        possible_wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
        ]
        for wl in possible_wordlists:
            if os.path.exists(wl):
                wordlist = wl
                print(f"[+] Menggunakan wordlist: {wordlist}")
                break
        if wordlist is None:
            print("[!] Tidak ada wordlist ditemukan. Buat wordlist sederhana...")
            wordlist = os.path.join(workspace_dir, 'temp_wordlist.txt')
            with open(wordlist, 'w') as f:
                f.write("admin\nlogin\napi\ntest\nbackup\nconfig\n")

    output_file = os.path.join(workspace_dir, 'ffuf_output.json')
    # Gunakan https? Bisa juga disesuaikan dengan skema dari domain
    # Di sini kita asumsikan http, tapi domain mungkin sudah include skema
    if domain.startswith('http'):
        base_url = domain.rstrip('/') + '/FUZZ'
    else:
        base_url = f"http://{domain}/FUZZ"
    
    cmd = f"ffuf -u {base_url} -w {wordlist} -ac -of json -o {output_file} -t 50 -p 0.5"
    if cookies_file and os.path.exists(cookies_file):
        # ffuf menerima cookies dengan -b "name=value; name2=value2"
        with open(cookies_file, 'r') as f:
            cookie_content = f.read().strip()
        # Ubah format Netscape ke format ffuf (name=value; ...) sederhana
        # Untuk Netscape, kita bisa parsing tapi untuk sederhana kita ambil baris yang bukan komentar
        # Di sini kita asumsikan cookies_file berisi format name=value (sederhana)
        cmd += f" -b '{cookie_content}'"

    print(f"[*] Perintah: {cmd}")
    print("[*] Proses mungkin memakan waktu. Tekan Ctrl+C untuk menghentikan...")

    try:
        stdout, stderr, rc = run_command(cmd, timeout=timeout)
        save_raw_output(workspace_dir, 'recon', 'ffuf_raw', stdout + stderr, 'txt')

        found = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    data = json.load(f)
                    for r in data.get('results', []):
                        found.append({
                            'url': r.get('url'),
                            'status': r.get('status'),
                            'length': r.get('length')
                        })
                except json.JSONDecodeError as e:
                    print(f"[!] Gagal parse JSON: {e}")

        with open(os.path.join(workspace_dir, 'content_discovery.json'), 'w') as f:
            json.dump(found, f, indent=2)

        print(f"[+] Ditemukan {len(found)} endpoint/direktori.")
        return found
    except Exception as e:
        print(f"[!] Content discovery error: {e}")
        return []