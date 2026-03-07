def get_user_choice(prompt, options, default=None):
    """Tampilkan pilihan dan minta user memilih."""
    print(prompt)
    for i, opt in enumerate(options, 1):
        print(f"  [{i}] {opt}")
    if default:
        print(f"Pilihan Anda (default {default}): ", end='')
    else:
        print("Pilihan Anda: ", end='')
    choice = input().strip()
    if not choice and default:
        return default
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            return options[idx]
        else:
            print("Pilihan tidak valid. Coba lagi.")
            return get_user_choice(prompt, options, default)
    except ValueError:
        print("Input harus angka.")
        return get_user_choice(prompt, options, default)

def confirm_action(msg):
    """Minta konfirmasi ya/tidak."""
    resp = input(f"{msg} (y/n): ").strip().lower()
    return resp == 'y'