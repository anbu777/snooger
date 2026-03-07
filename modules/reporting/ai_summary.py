def generate_summary(ai_engine, report_data):
    if ai_engine.mode == 'off':
        return "AI summary tidak tersedia (mode non-AI)."
    prompt = f"""
    Berikut adalah hasil penetration testing pada target {report_data['metadata']['target']}.
    Ditemukan {len(report_data['vulnerabilities'])} kerentanan.
    Detail kerentanan:
    """
    for v in report_data['vulnerabilities'][:10]:
        name = v.get('info', {}).get('name', 'Unknown')
        severity = v.get('info', {}).get('severity', 'unknown')
        prompt += f"- {name} ({severity})\n"
    prompt += "\nBuat ringkasan eksekutif singkat dalam bahasa Indonesia, termasuk rekomendasi perbaikan."
    response = ai_engine.ask(prompt, task_type='summary')
    return response if response else "Gagal menghasilkan ringkasan."