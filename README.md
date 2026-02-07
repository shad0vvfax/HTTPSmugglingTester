'url', help='Target URL (e.g., https://example.com or 192.168.1.1)')  
'-t', '--timeout', type=int, default=10,  
help='Request timeout in seconds (default: 10)')  
'-d', '--delay', type=int, default=1,  
help='Delay between tests in seconds (default: 1)')  
'-v', '--verbose', action='store_true',  
help='Show detailed output including requests/responses and explanations')  
