import pandas as pd
import matplotlib.pyplot as plt

# Load the data
df = pd.read_csv("/home/sdnuser/sdn-thesis/logs/detector_signals.csv")
df_5s = df[df["window"] == "5s"].reset_index(drop=True)

fig, ax = plt.subplots(figsize=(10, 4))

ax.plot(df_5s.index, df_5s["entropy"], label="Entropy H(w)", color="blue", linewidth=1.5)

if "alert" in df_5s.columns:
    attack_rows = df_5s[df_5s["alert"] == 1]
    ax.scatter(attack_rows.index, attack_rows["entropy"], color="red", s=20, label="Alert raised", zorder=5)

ax.set_xlabel("Window cycle")
ax.set_ylabel("Entropy (bits)")
ax.set_title("Entropy Signal and Alerts (5s window)")
ax.legend(loc="upper left")
ax.grid(True, alpha=0.3)

plt.tight_layout()

plt.savefig("/home/sdnuser/sdn-thesis/logs/oakf_adaptation_5s.png", dpi=150)
print("Plot successfully saved to /home/sdnuser/sdn-thesis/logs/oakf_adaptation_5s.png")