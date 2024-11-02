#!/usr/bin/env python3

import argparse
import datetime
import os
import pyotp
import qrcode
import json
from qrcode.image.pure import PymagingImage
from pathlib import Path

def generate_2fa_config(access_key, interval):
    # Generate a random secret key
    secret = pyotp.random_base32()

    totp = pyotp.TOTP(secret, interval=interval)

    # Generate provisioning URI for QR code
    provisioning_uri = totp.provisioning_uri(
        name=access_key,
        issuer_name="Knock-Port"
    )

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Create config directory if it doesn't exist
    config_dir = Path("config/2fa")
    config_dir.mkdir(parents=True, exist_ok=True)

    # Save 2FA configuration
    config = {
        "secret": secret,
        "interval": interval,
        "created_at": str(datetime.datetime.now())
    }

    config_file = config_dir / f"{access_key}.json"
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

    # Save QR code image
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(config_dir / f"{access_key}_qr.png")

    # Print ASCII QR code
    print("\n=== QR Code ===")
    qr.print_ascii(tty=True)
    print("\n=== 2FA Setup Instructions ===")
    print("1. Open Google Authenticator on your phone")
    print("2. Tap the '+' button")
    print("3. Choose 'Scan a QR code'")
    print(f"4. Scan the QR code saved in: config/2fa/{access_key}_qr.png")
    print("\nAlternatively, you can manually enter this secret:")
    print(f"Secret: {secret}")
    print("\nConfiguration has been saved to:")
    print(f"config/2fa/{access_key}.json")
    print("\nMake sure to keep these files secure!")

def main():
    parser = argparse.ArgumentParser(description="Setup 2FA for KnockPort access key")
    parser.add_argument('-k', '--http_access_key', type=str, required=True, help='HTTP access key to associate with 2FA')
    parser.add_argument('-i', '--interval', type=int, default=30, help='2FA token refresh interval (default:30s)')
    args = parser.parse_args()

    generate_2fa_config(args.http_access_key, args.interval)

if __name__ == "__main__":
    main()
