import argparse
import os
import shutil
import time

from transformers import AutoTokenizer


def main():
    parser = argparse.ArgumentParser(description="Package training artifacts")
    parser.add_argument("--dst", default="artifacts", help="Destination folder")
    args = parser.parse_args()

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(args.dst, ts)
    os.makedirs(out_dir, exist_ok=True)

    for fname in ["fileless_detector.pt", "fileless_detector_cfg.json", "events.csv"]:
        if os.path.exists(fname):
            shutil.copy(fname, os.path.join(out_dir, fname))
        else:
            print(f"[warn] missing {fname}")
    # save tokenizer for offline inference
    try:
        tok = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        tok.save_pretrained(os.path.join(out_dir, "tokenizer"))
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] could not save tokenizer: {exc}")
    print(f"artifacts saved to {out_dir}")


if __name__ == "__main__":
    main()