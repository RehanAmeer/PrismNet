# PrismNet
PrismNet is a software tool built to monitor and analyze network traffic in real time. It captures raw data moving through your computer and breaks it down into readable information.
The project connects a fast backend engine written in C++ with a clean, visual web dashboard that anyone can use in their browser to see data as it travels.
Key Features
•	Instant View: Captures and displays network data immediately without annoying delays.
•	Protocol Identification: Automatically separates common types of traffic like web browsing (TCP), basic data transfers (UDP), and network testing pings (ICMP).
•	Payload Reader: Shows the actual contents of the data packet in both raw numbers (Hexadecimal) and readable text (ASCII).
•	Live Statistics: Keeps a running count of total packets, the biggest packet captured, and average sizes.
•	Smart Labeling: Recognizes and labels common services such as HTTP for websites or DNS for address lookups based on port numbers.
•	Import & Export: Saves captured data to a CSV file or lets you load an old file to review saved data.

Prerequisites & Setup
What you need:
OS: Linux (Ubuntu/Debian) or Windows with WSL2.  

Tools: g++ compiler and libpcap libraries.  

Installation:
Install dependencies:
sudo apt update && sudo apt install build-essential libpcap-dev

Compile the project:
g++ main.cpp -o prismnet -lpcap -lpthread

Run PrismNet:
sudo ./prismnet (Requires sudo to access the network card)

How to Use It
After running the program, open your browser and go to http://localhost:8080.  
Click the Start button to begin the live feed.  
Use the Search bar to filter for specific IP addresses or protocols.  
Click any row in the table to see the Packet Details panel with the raw data dump.

Core Logic
The Backend (C++): Uses libpcap to "sniff" data from your network card. It parses the Ethernet, IP, and Transport layers to find out who is talking to whom.
The Frontend (HTML/JS): A localized web server sends the captured data to your browser as a clean JSON feed.
Safety First: Uses a "Mutex" lock to ensure that the thread capturing data and the thread showing it to you don't crash into each other.

Project Structure
main.cpp: The engine that captures packets and runs the web server.
index.html: The visual dashboard with light/dark mode and live polling.


