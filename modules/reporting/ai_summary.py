def generate_summary(ai_engine, report_data):
    if ai_engine.mode == 'off':
        return "AI summary tidak tersedia (mode non-AI)."
    prompt = f"""
    Berikut adalah hasil penetration testing pada target {report_data['metadata']['target']}.
    Ditemukan {len(report_data.get('vulnerabilities', []))} kerentanan dari nuclei, {len(report_data.get('validated_findings', []))} terverifikasi, dan {len(report_data.get('idor_findings', []))} IDOR.
    Detail kerentanan:
    """
    # Pastikan vulnerabilities adalah list of dicts
    vulns = report_data.get('vulnerabilities', [])
    if vulns and isinstance(vulns, list):
        for v in vulns[:10]:
            if isinstance(v, dict):
                name = v.get('info', {}).get('name', 'Unknown')
                severity = v.get('info', {}).get('severity', 'unknown')
                prompt += f"- {name} ({severity})\n"
            else:
                prompt += f"- Unknown (invalid format)\n"
    prompt += "\nBuat ringkasan eksekutif singkat dalam bahasa Indonesia, termasuk rekomendasi perbaikan."
    response = ai_engine.ask(prompt, task_type='summary')
    return response if response else "Gagal menghasilkan ringkasan."