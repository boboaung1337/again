import hashlib

def generate_hashes_only(range_str):
    """
    Generate and display only MD5 hashes for a range of numbers
    Returns list of hashes
    """
    try:
        # Split the range string
        parts = range_str.split('-')
        if len(parts) != 2:
            raise ValueError("Range should be in format 'start-end'")
        
        start = int(parts[0].strip())
        end = int(parts[1].strip())
        
        if start > end:
            start, end = end, start  # Swap if start > end
        
        # Generate hashes for the range
        hashes = []
        for num in range(start, end + 1):
            hash_val = hashlib.md5(str(num).encode()).hexdigest()
            hashes.append(hash_val)
        
        return hashes
    
    except ValueError as e:
        print(f"Error: {e}")
        return []

def main():
    """Interactive script to generate only MD5 hashes"""
    print("MD5 Hash Generator (Hashes Only)")
    print("=================================")
    print("Enter ranges in format: start-end (e.g., 1-10, 50-150)")
    print("Enter 'quit' or 'exit' to stop")
    print("-" * 40)
    
    while True:
        try:
            user_input = input("\nEnter range: ").strip()
            
            # Exit conditions
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            # Check if it's a range
            if '-' in user_input:
                hashes = generate_hashes_only(user_input)
                
                if hashes:
                    # Display only hashes
                    for hash_val in hashes:
                        print(hash_val)
                    
                    # Optional: Show count
                    print(f"\nTotal hashes: {len(hashes)}")
                    
                    # Optional save option
                    save = input("\nSave to file? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Filename (default: hashes.txt): ").strip() or "hashes.txt"
                        with open(filename, 'w') as f:
                            f.write('\n'.join(hashes))
                        print(f"Saved to {filename}")
                
                else:
                    print("No hashes generated. Check your input format.")
            
            else:
                # Handle single number
                try:
                    num = int(user_input)
                    hash_val = hashlib.md5(str(num).encode()).hexdigest()
                    print(hash_val)
                except ValueError:
                    print("Please enter a range (e.g., 1-10) or single number")
        
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

if __name__ == "__main__":
    main()
