#!/usr/bin/env python3
"""LoRA fine-tune of Cohere Tiny Aya on the curated Wazuh alert-analyst data with AlignTune.

Meant for a free Colab T4 or a Kaggle T4/P100. Needs: `pip install aligntune`, a Hugging Face
token with access to CohereLabs/tiny-aya-global (accept the licence on the model page first).

  python train/train_sft.py --dataset <hf-user>/wazuh-alert-analyst --out /content/out
  python train/train_sft.py --dataset data/curated/train/train/messages.jsonl --out out   (local file)

Afterwards (AlignTune CLI):
  aligntune export merge_adapter <out> --output <out>/merged
  aligntune export gguf <out>/merged --output <out>/gguf -q Q4_K_M -c llama-cpp
  aligntune export hf_hub <out> --repo <hf-user>/tiny-aya-wazuh-analyst-lora --adapter-only
"""
import argparse
import json
import time
from pathlib import Path

import torch
from aligntune.core.backend_factory import create_sft_trainer

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="CohereLabs/tiny-aya-global")
ap.add_argument("--dataset", required=True, help="HF dataset repo (config train_messages) or a local messages.jsonl")
ap.add_argument("--subset", default="train_messages")
ap.add_argument("--out", default="./out")
ap.add_argument("--backend", default="trl", help="chat_completion is only supported by the TRL backend (Unsloth: sft/pretraining/instruction_following)")
ap.add_argument("--epochs", type=float, default=2)
ap.add_argument("--max-steps", type=int, default=-1)
ap.add_argument("--max-samples", type=int, default=None)
ap.add_argument("--batch", type=int, default=2)
ap.add_argument("--grad-accum", type=int, default=8)
ap.add_argument("--lr", type=float, default=2e-4)
ap.add_argument("--seq", type=int, default=2048)
ap.add_argument("--lora-r", type=int, default=16)
ap.add_argument("--no-4bit", action="store_true")
ap.add_argument("--seed", type=int, default=42)
a = ap.parse_args()

bf16 = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
local = a.dataset.endswith(".jsonl")
kw = {}
if not local:
    kw["subset"] = a.subset
if not a.no_4bit:
    kw["quantization"] = {"load_in_4bit": True, "bnb_4bit_quant_type": "nf4", "bnb_4bit_compute_dtype": "bfloat16" if bf16 else "float16"}

t0 = time.time()
trainer = create_sft_trainer(
    model_name=a.model,
    dataset_name=a.dataset,
    backend=a.backend,
    output_dir=a.out,
    # "sft" (not "chat_completion"): AlignTune only keeps the full system/user/assistant
    # `messages` list for SFT and instruction_following; other task types reduce
    # conversations to CuratorKIT's flattened prompt/completion form.
    # No format_type: "messages" is not a CuratorKIT format (every row is rejected);
    # CuratorKIT's auto-detection accepts the role/content list as is.
    task_type="sft",
    chat_template="auto",
    num_epochs=a.epochs,
    max_steps=a.max_steps,
    max_samples=a.max_samples,
    batch_size=a.batch,
    gradient_accumulation_steps=a.grad_accum,
    learning_rate=a.lr,
    lr_scheduler_type="cosine",
    warmup_ratio=0.05,
    max_seq_length=a.seq,
    use_peft=True,
    lora_r=a.lora_r,
    lora_alpha=2 * a.lora_r,
    lora_dropout=0.05,
    lora_target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    bf16=bf16,
    fp16=not bf16,
    gradient_checkpointing=True,
    logging_steps=10,
    save_steps=100,
    save_total_limit=2,
    seed=a.seed,
    **kw,
)
result = trainer.train()
path = trainer.save_model()
Path(a.out).mkdir(parents=True, exist_ok=True)
json.dump({"args": vars(a), "train_result": result if isinstance(result, dict) else str(result),
           "model_path": str(path), "minutes": round((time.time() - t0) / 60, 1),
           "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu"},
          open(Path(a.out) / "train_summary.json", "w"), indent=1, default=str)
print("saved to", path, f"in {(time.time() - t0) / 60:.1f} min")
