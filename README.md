# ProtOSINT
ProtOSINT is a Python script that helps you investigate Protonmail accounts and ProtonVPN IP addresses.

![](https://github.com/pixelbubble/pixelbubble/blob/main/protosint.gif)

## Description
This tool can help you in your OSINT investigation on Proton service (for educational purposes only).  
ProtOSINT is separated in 3 sub-modules:
- [1] Test the validity of one protonmail account
- [2] Try to find if your target have a protonmail account by generating multiple adresses by combining information fields inputted
- [3] Find if your IP is currently affiliate to ProtonVPN

## Prerequisite

   [Python 3](https://www.python.org/downloads/)

## Usage

```bash
python3 protosint.py
```

## Protonmail 
The local part of a protonmail account is case-insensitive.
It's mean that if "mikemike@protonmail.com" is valid, is it possible that Mike Mike use other email combinaison like :
- "mike.mike@protonmail.com"
- "mike_mike@protonmail.com"
- "mike-mike@protonmail.com"
- "mike.mike+paypal@protonmail.com"
> All of these emails have the save timestamp and are linked to the same main account

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)
