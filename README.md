# ProtOSINT
ProtOSINT is a Python script that helps you investigate ProtonMail accounts and ProtonVPN IP addresses.

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
The account name in the protonmail is case-insensitive and ProtonMail considers the "." "_" "-" symbols as transparent.  
Additionnaly, any words put after a "+" sign are not taken into account.  
It means that all of these email adresses below are the same as mikemike@protonmail.com :  
- "mike.mike@protonmail.com"
- "mike_mike@protonmail.com"
- "mike-mike@protonmail.com"
- "mike.mike+paypal@protonmail.com"
>All of these emails have the save timestamp and refers to the account mikemike@protonmail.com

This technique does not always give you the creation time and date of the ProtonMail account itself, but the time and date when the email address itself was created (thanks to @sector035 for the tip : https://sector035.nl/articles/2020-50)

Email encryption keys

ProtOSINT allow you to know which encryption key is used for a protonmail account :
- RSA 2048-bit (Older but faster) - high security
- RSA 4096-bit (Secure but slow) - highest security
- X25519 (Modern, fastest, secure) - State-of-the-art 

## Contributing
Feel free to clone this project. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)
