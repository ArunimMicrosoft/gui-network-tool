# GUI Network Tool

## Overview
The GUI Network Tool is a Python application that provides a graphical user interface for performing network operations, specifically pinging hosts. It allows users to send ping requests and view the results in a user-friendly manner.

## Features
- Simple and intuitive GUI for sending ping requests.
- Displays ping results on a white canvas.
- Input validation for host addresses.
- Basic functionality to send pings and view results.

## Project Structure
```
gui-network-tool
├── src
│   ├── main.py          # Entry point of the application
│   ├── gui
│   │   └── canvas.py    # GUI canvas for displaying results
│   ├── network
│   │   └── ping.py      # Network operations for pinging hosts
│   └── utils
│       └── helpers.py    # Utility functions for the application
├── requirements.txt      # Project dependencies
└── README.md             # Project documentation
```

## Installation
To set up the project, follow these steps:

1. Clone the repository:
   ```
   git clone <repository-url>
   cd gui-network-tool
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage
To run the application, execute the following command:
```
python src/main.py
```

Once the application is running, you can enter a host address and click the "Send" button to perform a ping operation. The results will be displayed on the canvas.

## Dependencies
- `tkinter`: For creating the GUI.
- Additional libraries may be listed in `requirements.txt`.

## Contributing
Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.