from password_checker import check_password_strength
import encryption_tool
from intrusion_detection import basic_ids
import sys
import time
from utils import setup_logging
from threading import Thread, Event

log = setup_logging(__name__)

# background controller for IDS thread
background = {}


def main():
    while True:
        log.info("Starting Mini Security Suite")
        menu = """
--- MINI SECURITY SUITE ---
1) Check Password Strength
2) Encrypt/Decrypt Message
3) Run/Control IDS
4) Exit
"""
        print(menu)

        # validate choice
        while True:
            choice = input("Choice 1-4: ").strip()
            if choice in ("1", "2", "3", "4"):
                log.info("Selected option %s", choice)
                break
            log.warning("Invalid choice entered: %s", choice)
            print("Enter 1-4.")

        if choice == "1":
            print("\nPassword Strength Checker")
            pwd = input("Password: ")
            print(check_password_strength(pwd))
        elif choice == "2":
            print("\nEncryption Tool")
            encryption_tool.run_encryption_tool()
        elif choice == "3":
            print("\nIntrusion Detection System (IDS)")
            print("\nIDS Control Options:")
            print("1) Run IDS with specific number of checks (1-4)")
            print("2) Start/Stop Background IDS")
            print("3) Back to main menu")
            
            ids_choice = input("Choose option (1-3): ").strip()
            if not ids_choice in ("1", "2", "3"):
                log.warning("Invalid IDS choice: %s", ids_choice)
                print("Enter 1-3.")
                continue  # Go back to main menu
                
            log.info("Selected IDS option %s", ids_choice)
            if ids_choice == "3":
                continue  # Go back to main menu

            if ids_choice == "1":
                while True:
                    try:
                        num_checks = int(input("Enter number of checks (1-4): "))
                        if 1 <= num_checks <= 4:
                            log.info("Running IDS with %d checks", num_checks)
                            print(f"\nStarting IDS for {num_checks} checks...")
                            print("(Press Ctrl+C to stop early)\n")
                            basic_ids(max_checks=num_checks, interval=1.0, sleep_between=2.0)
                            print("\nIDS checks completed.")
                            break
                        log.warning("Invalid number of checks: %d", num_checks)
                        print("Enter a number between 1 and 4.")
                    except ValueError:
                        log.warning("Invalid input: must be a number")
                        print("Please enter a number.")
            elif ids_choice == "2":
                if background.get("thread") and background["thread"].is_alive():
                    print("\nBackground IDS is already running. Options:")
                    print("1) Stop IDS now")
                    print("2) Back to menu")
                    
                    while True:
                        stop_choice = input("\nChoice (1-2): ").strip()
                        if stop_choice in ("1", "2"):
                            break
                        print("Please enter 1 or 2")
                    
                    if stop_choice == "1":
                        print("\nStopping background IDS... ", end="", flush=True)
                        log.info("Stopping background IDS...")
                        
                        # Set the stop event
                        background["stop_event"].set()
                        
                        # Wait for the thread to finish with timeout
                        try:
                            start_time = time.time()
                            while background["thread"].is_alive() and time.time() - start_time < 10:
                                background["thread"].join(timeout=0.5)
                                print(".", end="", flush=True)
                                
                            if background["thread"].is_alive():
                                print("\nWarning: IDS thread taking longer than expected to stop...")
                                background["thread"].join(timeout=2)
                                
                        except Exception as e:
                            log.error("Error while stopping IDS: %s", str(e))
                            print(f"\nError stopping IDS: {str(e)}")
                        finally:
                            # Force cleanup
                            if background.get("thread") and background["thread"].is_alive():
                                log.warning("IDS thread did not stop gracefully, forcing cleanup...")
                                print("\nWarning: Forcing IDS cleanup...")
                            background.clear()
                            log.info("Background IDS stopped.")
                            print("\nBackground IDS has been stopped.")
                    else:
                        print("Returning to menu - IDS will continue running in background.")
                else:
                    log.info("Starting background IDS...")
                    
                    # Get number of checks from user
                    while True:
                        try:
                            num_checks = int(input("Enter number of checks (1-4): "))
                            if 1 <= num_checks <= 4:
                                log.info("Running background IDS with %d checks", num_checks)
                                break
                            log.warning("Invalid number of checks: %d", num_checks)
                            print("Enter a number between 1 and 4.")
                        except ValueError:
                            log.warning("Invalid input: must be a number")
                            print("Please enter a number.")
                    
                    # Clear any existing background data
                    background.clear()
                    
                    stop_event = Event()
                    def monitor_thread():
                        t = Thread(
                            target=basic_ids,
                            kwargs={
                                "max_checks": num_checks,
                                "interval": 1.0,
                                "sleep_between": 2.0,
                                "stop_event": stop_event
                            },
                            daemon=True
                        )
                        background["thread"] = t
                        background["stop_event"] = stop_event
                        t.start()
                        # Wait for thread to finish
                        t.join()
                        # Mark background as completed and store checks so main loop prints final message
                        background["completed"] = True
                        background["completed_checks"] = num_checks
                        background["completed_time"] = time.time()
                        log.info("Background IDS monitoring completed for %d checks", num_checks)

                    # Start a separate thread to monitor the IDS thread
                    monitor = Thread(target=monitor_thread, daemon=True)
                    monitor.start()

                    log.info("Background IDS started successfully.")
                    print(f"\nBackground IDS is now running for {num_checks} checks.")
                    print("It will stop automatically after completion.")
                    

        elif choice == "4":
            log.info("Application exit requested")
            print("Goodbye.")
            sys.exit(0)

        # If a background IDS monitoring session is running, wait for it to
        # complete before prompting the user. This prevents the menu or the
        # "Another task?" prompt from appearing while the IDS prints its
        # status messages; instead, the completion banner will be shown first.
        if background.get("thread") and background["thread"].is_alive():
            # Wait for monitor to mark completion
            try:
                while not background.get("completed"):
                    time.sleep(0.5)
            except KeyboardInterrupt:
                # allow user to interrupt waiting
                pass

            # Print completion banner (if present)
            if background.get("completed"):
                print("\n" + "="*50)
                print("IDS monitoring completed successfully.")
                print(f"Total checks performed: {background.get('completed_checks', 'N/A')}")
                print("="*50)
                print("\nIDS monitoring has completed.")
                print("Choose option 3 -> 2 to start another monitoring session.")
                # clear background state after notifying user
                background.clear()

        # ask to continue (normal flow)
        while True:
            again = input("Another task? (y/n): ").strip().lower()
            if again in ("y", "n"):
                log.debug("Continue response: %s", again)
                break
            log.warning("Invalid continue response: %s", again)
            print("Enter y or n.")
        if again == "n":
            log.info("Application exit requested")
            print("Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    main()
