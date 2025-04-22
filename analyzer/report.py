import json
import datetime

def generate_report(analysis_data, output_path):
    """
    Generate a JSON report from analysis results.
    
    Args:
        analysis_data (dict): Analysis results.
        output_path (str): Path to save the report.
    """
    # Add timestamp to report
    analysis_data["timestamp"] = datetime.datetime.utcnow().isoformat()
    try:
        # Write report to file
        with open(output_path, "w") as f:
            json.dump(analysis_data, f, indent=4, sort_keys=True)
    except IOError as e:
        # Handle file write errors
        raise ValueError(f"Failed to write report: {str(e)}")