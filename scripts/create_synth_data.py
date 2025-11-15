import pandas as pd
import numpy as np

node_list = [f"n{i}" for i in range(1, 8)]
client_list = [chr(i) for i in range(65, 75)]

rand_gen = lambda x: np.random.randint(0, x)
rand_choose = lambda x: np.random.choice(x)
rand_tran = lambda : f"({rand_choose(client_list)}, {rand_choose(client_list)}, {rand_gen(10)})"

def random_transaction():
    clients = np.random.choice(client_list, size=2, replace=False)
    if np.random.rand() < 0.5:
        return f"({clients[0]})"
    amount = np.random.randint(1, 10)
    return f"({clients[0]}, {clients[1]}, {amount})"

def create_testset(id, n):
    info_dict = {
        "Set Number" : [str(id)] + [""] * (n-1),
        "Transactions" : [random_transaction() for _ in range(n)],
        "Live" : ["[" + ", ".join(node_list) + "]"] +[""] * (n-1),
        "Byzantine" : ["[]"] + [""]* (n-1),
        "Attack" : ["[]"] + [""]* (n-1)
    }
    return pd.DataFrame(info_dict)
    
def main():
    create_testset(1, 50000).to_csv("testdata/synth_big.csv", index=False)
    create_testset(1, 10000).to_csv("testdata/synth.csv", index=False)
    create_testset(1, 1000).to_csv("testdata/synth_small.csv", index=False)

if __name__ == "__main__":
    main()