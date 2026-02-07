import sys 
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from label_generator import generate_benign_labels, generate_obvtunneling_labels, generate_evatunneling_labels
from dnsanalyzers import EntropyDNSAnalyzer
import csv
from plot_entropy_test import plot_entropy


def main():
    # Generate CSV with x benign, obvious tunneling, and evasing tunneling labels
    generate_benign_labels("dnslabelstest.csv")
    generate_obvtunneling_labels("dnslabelstest.csv")
    generate_evatunneling_labels("dnslabelstest.csv")

    # Read in all those label, class pairs and compute the entropy value/label length
    # Store [label, class, entropy, label_length] lists in a list
    entropy_analyzer = EntropyDNSAnalyzer()
    csv_file = open("dnslabelstest.csv", 'r')
    csv_reader = csv.reader(csv_file)
    next(csv_reader)
    plot_list = []
    for label, tunneling_class in csv_reader:
        entropy = entropy_analyzer._shannon_entropy(label)
        label_length = len(label)
        plot_list.append([label, tunneling_class, entropy, label_length])
 
    # Plot all the points on a graph
    plot_entropy(plot_list)

if __name__ == "__main__":
    main()