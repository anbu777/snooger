import sys
import logging

logger = logging.getLogger('snooger')

def get_user_choice(prompt: str, options: list, default: int = 1) -> str:
    """Interactive numbered choice menu."""
    print(f"\n{prompt}")
    for i, opt in enumerate(options, 1):
        marker = " (default)" if i == default else ""
        print(f"  [{i}] {opt}{marker}")
    while True:
        try:
            raw = input(f"Choice [1-{len(options)}]: ").strip()
            if not raw and default:
                if 1 <= default <= len(options):
                    return options[default - 1]
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                return options[idx]
            print(f"  Please enter a number between 1 and {len(options)}")
        except ValueError:
            print("  Please enter a valid number.")
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Interrupted.")
            sys.exit(0)

def get_user_input(prompt: str, default: str = '') -> str:
    """Get free text input from user."""
    try:
        display = f" [{default}]" if default else ""
        raw = input(f"{prompt}{display}: ").strip()
        return raw if raw else default
    except (EOFError, KeyboardInterrupt):
        return default

def confirm_action(msg: str, default: bool = False) -> bool:
    """Yes/no confirmation prompt."""
    default_hint = "Y/n" if default else "y/N"
    try:
        resp = input(f"{msg} ({default_hint}): ").strip().lower()
        if not resp:
            return default
        return resp in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        return False
