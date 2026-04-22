# MTK Wireshark Scripts

Just some Lua scripts for parsing MediaTek protocols in Wireshark. 
Code is currently kinda trashy, but hopefully I will find time to patch it :)

### Status: WIP
This is still a work in progress. It tracks the flow of commands—if the host asks for a ChipID or Efuse, the script labels the incoming data so you don't have to guess what it is.

### How to use
The easiest way to see the flow is to open **Expert Information** in Wireshark. It’ll give you a clean, chronological list of every command, response, and log message.

### Setup
Drop the `.lua` file into your Wireshark plugins folder and reload (`Ctrl+Shift+L`).

<img width="2560" height="1399" alt="image" src="https://github.com/user-attachments/assets/a2262fef-1b6e-4787-88d9-b1255b4b7abe" />
