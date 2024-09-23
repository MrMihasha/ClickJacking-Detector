import requests
from bs4 import BeautifulSoup
from colorama import init, Fore

init(autoreset=True)

ascii_art = r"""

               ⣀⣀⡀⡀⢀⠀⠀⠀⠤⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠠⠤⠄⣐⣀⣀⣀⣀⣀⣀⣀⣀⣤⣤⣤⣤⠄
               ⠈⢻⣿⣟⠛⠛⠛⠛⠛⠓⠒⣶⣦⣬⣭⣃⣒⠒⠤⢤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡶⢒⣚⣫⣭⣧⣶⣶⣿⣿⡛⠉⠉⠉⠉⠉⠉⣽⣿⠟⠁⠀
               ⠀⠀⠙⢿⡄⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣧⠉⠛⠻⢷⣬⡙⠣⡄⠀⠀⠀⠀⠀⠀⠀⡠⠚⣡⡾⠟⠋⠁⠀⣾⡿⠉⣿⣷⣶⠀⠀⠀⠀⠀⣰⠟⠁⠀⠀⠀
               ⠀⠀⠀⠀⠻⣄⠀⠀⠀⠀⣿⣿⠀⣿⣿⣿⠀⠀⠀⠀⠈⠑⢄⠀⠀⠀⠀⠀⠀⠀⠀⢀⠔⠁⠀⠀⠀⠀⠀⢿⣿⣏⣀⣾⣿⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀
               ⠀⠀⠀⠈⠀⢛⣷⣤⣄⣀⣙⣿⣿⣿⣿⡃⠀⠀⠀⠀⠀⠀⡀⠀⠀⡀⠀⠀⠀⡠⠀⠀⠀⠀⠀⠀⠀⠄⠠⠈⠿⠿⠿⠿⠥⠤⠶⠶⠿⠁⠀⠀⠀⠀⠀⠀
               ⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠁⠀⠀⠃⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
  ___ _ _    _      _         _   _             ___      _          _                        
 / __| (_)__| |___ | |__ _ __| |_(_)_ _  __ _  |   \ ___| |_ ___ __| |_ ___ _ _              
| (__| | / _| / / || / _` / _| / / | ' \/ _` | | |) / -_)  _/ -_) _|  _/ _ \ '_|             
 \___|_|_\__|_\_\\__/\__,_\__|_\_\_|_||_\__, | |___/\___|\__\___\__|\__\___/_|               
    ________ __  __ __     __                     ____  ___    __  ____ __            __        _ 
  _/_/ ___(_) /_/ // /_ __/ /   _______  __ _   _/_/  |/  /___/  |/  (_) /  ___ ____ / /  ___ _| |
 / // (_ / / __/ _  / // / _ \_/ __/ _ \/  ' \_/_// /|_/ / __/ /|_/ / / _ \/ _ `(_-</ _ \/ _ `// /
/ / \___/_/\__/_//_/\_,_/_.__(_)__/\___/_/_/_/_/ /_/  /_/_/ /_/  /_/_/_//_/\_,_/___/_//_/\_,_//_/ 
|_|                                                                                         /_/   

"""

lines = ascii_art.splitlines()

colors = [Fore.RED, Fore.YELLOW, Fore.LIGHTYELLOW_EX]

for i, line in enumerate(lines):
    print(colors[i % len(colors)] + line)

def check_headers(response):
    x_frame_options = response.headers.get('X-Frame-Options')
    csp = response.headers.get('Content-Security-Policy')
    
    print("X-Frame-Options:", x_frame_options)
    
    if csp:
        print("CSP:", csp.split(';')[0])  
    else:
        print(Fore.RED + "CSP header is missing.")

    if x_frame_options:
        if "DENY" in x_frame_options:
            print(Fore.GREEN + "Protected (X-Frame-Options: DENY).")
        elif "SAMEORIGIN" in x_frame_options:
            print(Fore.GREEN + "Protected (X-Frame-Options: SAMEORIGIN).")
        else:
            print(Fore.RED + "Vulnerable (X-Frame-Options: " + x_frame_options + ").")
    else:
        print(Fore.RED + "Vulnerable (X-Frame-Options is missing).")

def check_iframes(html):
    soup = BeautifulSoup(html, 'html.parser')
    iframes = soup.find_all('iframe')
    if iframes:
        print(Fore.YELLOW + f"Found {len(iframes)} iframe(s).")
        for idx, iframe in enumerate(iframes):
            print(Fore.YELLOW + f"Iframe {idx + 1}: {iframe.get('src')}")
    else:
        print(Fore.RED + "No iframes found.")

def clickjacking_detector(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        check_headers(response)
        check_iframes(response.text)

    except requests.RequestException as e:
        print(Fore.RED + f"An error occurred: {e}")

if __name__ == "__main__":
    while True:
        target_url = input("Please enter the URL of the site to check: ")
        clickjacking_detector(target_url)

        again = input("Do you want to scan another site? (y/n): ").strip().lower()
        if again != 'y':
            print("Exiting the program. Goodbye!")
            break
