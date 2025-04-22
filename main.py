import argparse
import sys
import os
from analyzer.pe_analyzer import analyze_pe
from analyzer.elf_analyzer import analyze_elf
from analyzer.report import generate_report

def parse_arguments():
    # Initialize argument parser with description
    parser = argparse.ArgumentParser(description="Binary File Analyzer for PE and ELF files")
    # Add required argument for file path
    parser.add_argument("--file", required=True, help="Path to the binary file")
    # Add required argument for file type (PE or ELF)
    parser.add_argument("--type", choices=["pe", "elf"], required=True, help="File type (pe or elf)")
    # Add optional argument for output report path
    parser.add_argument("--output", default="report.json", help="Path to save analysis report (default: report.json)")
    return parser.parse_args()

def main():
    # Parse command-line arguments
    args = parse_arguments()
    
    # Verify if input file exists
    if not os.path.isfile(args.file):
        print(f"Error: File '{args.file}' does not exist.")
        sys.exit(1)
    
    try:
        # Analyze based on file type
        if args.type == "pe":
            result = analyze_pe(args.file)
        else:  # args.type == "elf"
            result = analyze_elf(args.file)
        
        # Generate and save report
        generate_report(result, args.output)
        print(f"Analysis complete. Report saved to '{args.output}'.")
    
    except Exception as e:
        # Handle any analysis errors gracefully
        print(f"Error during analysis: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()