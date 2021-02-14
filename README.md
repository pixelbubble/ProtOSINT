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

## Tips for Protonmail investigation

### ProtonMail is case-insensitive

The account name in the ProtonMail is case-insensitive and ProtonMail considers the "." "_" "-" symbols as transparent.  
Additionnaly, any words put after a "+" sign are not taken into account.  
It means that all of these email adresses below are the same as mikemike@protonmail.com:  
- "mike.mike@protonmail.com"
- "mike_mike@protonmail.com"
- "mike-mike@protonmail.com"
- "mike.mike+paypal@protonmail.com"
>All of these emails have the save timestamp and refers to the account mikemike@protonmail.com.

### Timestamp

ProtOSINT does not always give you the creation time of the ProtonMail account itself. The timestamp returned by ProtonMail API is the time and date when the primary PGP key for the email was created.

#### Example 1: my target keeps the default settings
In this case, ProtOSINT gives me the real date of creation of the ProtonMail account.
- 2021-01-12: Creation of the protonmail account "thisisatestemailaccount@protonmail.com"  
> Fingerprint of the key: 382a2045a09305f5ab4ef9000e1a2dd1e7e162fe - RSA (2048).
- 2021-01-15: ProtOSINT gives me the 2021-01-12 timestamps  

#### Example 2: my target changes the email encryption keys
In this case, ProtOSINT does not give me the "real" date of creation of the ProtonMail account but the date of creation of the primary PGP key.
- 2021-01-12: Creation of the protonmail account "thisisatestemailaccount@protonmail.com"  
> Fingerprint of the key: 382a2045a09305f5ab4ef9000e1a2dd1e7e162fe - RSA (2048).
- 2021-01-13: My target changes the primary PGP key (in settings/keys/Email encryption keys)  
> New fingerprint of the key: 634936a85115b8e30a31b94345d4551bc66da9d3 - RSA (2048).
- 2021-01-15: ProtOSINT gives me the 2021-01-13 timestamp and not the other (2021-01-12)

### Email encryption keys

ProtOSINT allow you to know which encryption key is used for a ProtonMail account:
- RSA 2048-bit (Older but faster) - high security
- RSA 4096-bit (Secure but slow) - highest security
- X25519 (Modern, fastest, secure) - State-of-the-art 

### Custom domain

In the first sub-module of ProtOSINT [1], you can import a custom domain like alias@mycustumdomain.com.
In fact, the premium ProtonMail plan allows you to connect your custom domain to ProtonMail.
This means that if alias@mycustumdomain.com is "valid", your target uses a premium ProtonMail account.

## Contributing
Feel free to clone this project. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)
