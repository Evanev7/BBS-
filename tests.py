from random import randint
num_attempts = 200
num_messages = 2000

num_true_positives = 0
num_false_positives = 0
num_true_negatives = 0
num_false_negatives = 0

import BBS
for i in range(num_attempts):
    gm = BBS.GM(max_messages=num_messages)
    msgs = [randint(0,10000) for _ in range(num_messages)]
    false_msgs = [randint(0,10000) for _ in range(num_messages)]
    sig = gm.sign(msgs)
    
    if gm.verify(sig, msgs) == True:
        num_true_positives += 1
    else:
        num_false_negatives += 1
    if gm.verify(sig, false_msgs) == False:
        num_true_negatives += 1
    else:
        num_false_negatives += 1

print(f"""      {num_attempts} test runs over {num_attempts*num_messages} messages
      {num_true_positives} correctly verified
      {num_false_positives} incorrectly verified
      {num_true_negatives} correctly dismissed
      {num_false_negatives} incorrectly dismissed""")

assert(num_false_positives == 0)
assert(num_false_negatives == 0)
