from Crypto.PublicKey import RSA

private = RSA.generate(4096)
with open('private.pem', 'w') as f:
    f.write(private.exportKey())

public = private.publickey()
with open('public.pem', 'w') as f:
    f.write(public.exportKey())
