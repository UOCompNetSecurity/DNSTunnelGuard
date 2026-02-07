import matplotlib.pyplot as plt

def plot_entropy (data : list[list]) -> None:
    colors = {"benign": "green", "evasive_tunneling": "orange", "obvious_tunneling": "red"}

    for label, tunneling_class, entropy, label_length in data:
        plt.scatter(label_length, entropy, color=colors[tunneling_class], alpha=0.7)

    plt.xlabel("Label Length")
    plt.ylabel("Shannon Entropy")
    plt.title("DNS Label Entropy and Length")

    for tunneling_class, color in colors.items():
        plt.scatter([], [], color=color, label=tunneling_class)

    plt.legend()
    plt.grid(True)
    plt.show()