from random import randint
num_attempts = 200
num_messages = 2000
num_users = 1000


import BBS

def test_message_signing(num_attempts, num_messages):
    
    num_true_positives = 0
    num_false_positives = 0
    num_true_negatives = 0
    num_false_negatives = 0

    params = BBS.TrustedPublicAuthority.GGen(max_messages=num_messages)
    for _ in range(num_attempts):
        gm = BBS.GM(params=params)
        user = BBS.User(params=params)
        channel = BBS.InsecureChannel()
        msgs = [randint(0,10000) for _ in range(num_messages)]
        false_msgs = [randint(0,10000) for _ in range(num_messages)]
        sig = channel.user_sign(user, gm, msgs)
        
        if BBS.TrustedPublicAuthority.verify(params, gm.public_key, sig, msgs) == True:
            num_true_positives += 1
        else:
            num_false_negatives += 1
        if BBS.TrustedPublicAuthority.verify(params, gm.public_key, sig, false_msgs) == False:
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

    return channel

def user_join_sequence(num_users):
    gm = BBS.GM()
    channel = BBS.InsecureChannel()

    for _ in range(num_users):
        user = BBS.User()
        channel.join(gm=gm, user=user)
    
    print(f"        {len(gm.Reg)} users successfully registered with GM")

    # channel.leaked_data contains a reference to any data leaked in the insecure channel.




if __name__ == "__main__":
    test_message_signing(num_attempts=num_attempts, num_messages=num_messages)
#    user_join_sequence(num_users=num_users)