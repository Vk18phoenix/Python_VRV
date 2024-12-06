import csv
from collections import defaultdict, Counter

# Configurable Threshold for Suspicious Activity
FAILED_LOGIN_THRESHOLD = 10

# Function to parse log file and process data
def process_log_file(log_file_path):
    ip_requests = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)
    
    with open(log_file_path, 'r') as file:
        for line in file:
            # Split the log line to extract information
            parts = line.split()
            if len(parts) < 9:
                continue
            
            ip = parts[0]
            request = parts[5].strip('"')  # GET, POST, etc.
            endpoint = parts[6]
            status_code = parts[8]
            
            # Count requests per IP
            ip_requests[ip] += 1
            
            # Count endpoint accesses
            endpoint_counts[endpoint] += 1
            
            # Check for failed login attempts (HTTP 401 or similar messages)
            if status_code == "401" or "Invalid credentials" in line:
                failed_logins[ip] += 1
    
    return ip_requests, endpoint_counts, failed_logins

# Function to detect suspicious activity
def detect_suspicious_activity(failed_logins):
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

# Function to save results to a CSV file
def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activities, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])
        
        # Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])
        
        # Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main function
def main():
    log_file_path = "sample.log"  # Update the path if the log file is elsewhere
    output_file = "log_analysis_results.csv"
    
    # Process the log file
    ip_requests, endpoint_counts, failed_logins = process_log_file(log_file_path)
    
    # Identify the most frequently accessed endpoint
    most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1])
    
    # Detect suspicious activity
    suspicious_activities = detect_suspicious_activity(failed_logins)
    
    # Display results
    print("Requests per IP:")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20} {count}")
    
    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activities, output_file)
    print(f"\nResults saved to {output_file}")

# Entry point
if __name__ == "__main__":
    main()
