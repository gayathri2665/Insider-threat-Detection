import sys
import argparse
from src.cli import CLIAdminConsole

def main():
    parser = argparse.ArgumentParser(
        description="Real-Time Insider Threat Detection Framework for Database Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  init-db    Initialize the database schema and generate baseline logs.
  train      Generate user behavioral profiles and train Evidential neural networks.
  monitor    Launch real-time monitoring engine (starts Wazuh Agent log shipper).
  trigger    Simulate database activity representing a specific threat scenario.
  feedback   Submit administrator review feedback on a generated alert.
  evaluate   Run performance evaluation benchmark and compare with baselines.
  status     Display system overview status, user profiles, and recent alerts.
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="System command to execute")
    
    # Init DB subcommand
    subparsers.add_parser("init-db", help="Initialize database schema and populate baseline history")
    
    # Train subcommand
    subparsers.add_parser("train", help="Extract session feature vectors and train anomaly detection models")
    
    # Monitor subcommand
    subparsers.add_parser("monitor", help="Start real-time monitoring and anomaly detection engine")
    
    # Trigger attack subcommand
    trigger_parser = subparsers.add_parser("trigger", help="Simulate a specific insider threat attack scenario")
    trigger_parser.add_argument(
        "--scenario",
        required=True,
        choices=[
            "mass_data_exfiltration",
            "privilege_escalation",
            "sql_injection",
            "off_hours_burst",
            "hijacked_service_account",
            "repeated_failed_logins"
        ],
        help="The specific attack scenario to trigger"
    )
    
    # Feedback subcommand
    feedback_parser = subparsers.add_parser("feedback", help="Submit administrator feedback on a security alert")
    feedback_parser.add_argument("--alert-id", type=int, required=True, help="The ID of the security alert")
    feedback_parser.add_argument(
        "--type",
        required=True,
        choices=["TRUE_POSITIVE", "FALSE_POSITIVE"],
        help="Feedback evaluation type"
    )
    feedback_parser.add_argument("--comments", default="", help="Optional administrator review comments")
    
    # Evaluate subcommand
    subparsers.add_parser("evaluate", help="Execute evaluation benchmark suite against baseline models")
    
    # Status subcommand
    subparsers.add_parser("status", help="Show registered database users, profiles and recent alerts")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    console = CLIAdminConsole()
    
    try:
        if args.command == "init-db":
            console.init_db()
        elif args.command == "train":
            console.train_models()
        elif args.command == "monitor":
            console.run_monitor()
        elif args.command == "trigger":
            console.trigger_attack(args.scenario)
        elif args.command == "feedback":
            console.submit_feedback(args.alert_id, args.type, args.comments)
        elif args.command == "evaluate":
            console.run_eval_suite()
        elif args.command == "status":
            console.show_status()
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error executing command '{args.command}': {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
