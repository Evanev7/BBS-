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
    
    num_passed_true_proofs = 0
    num_failed_false_proofs = 0

    params = BBS.TrustedPublicAuthority.GGen(max_messages=num_messages)
    for _ in range(num_attempts):
        gm = BBS.GM(params=params)
        user = BBS.User(params=params)
        channel = BBS.InsecureChannel()
        msgs = [randint(0,10000) for _ in range(num_messages)]
        false_msgs = [randint(0,10000) for _ in range(num_messages)]
        sig = channel.user_sign(user, gm, msgs)
        
        disclosed_msgs = {randint(0, num_messages-2) for _ in range(num_attempts)}
        if channel.partial_disclosure_proof(user, gm, sig, msgs, disclosed_msgs):
            num_passed_true_proofs += 1
        if not channel.partial_disclosure_proof(user, gm, sig, false_msgs, disclosed_msgs):
            num_failed_false_proofs += 1

        if BBS.TrustedPublicAuthority.verify(params, gm.public_key, sig, msgs) == True:
            num_true_positives += 1
        else:
            num_false_negatives += 1
        if BBS.TrustedPublicAuthority.verify(params, gm.public_key, sig, false_msgs) == False:
            num_true_negatives += 1
        else:
            num_false_positives += 1 
        
        

    print(f"""      {num_attempts} test runs over {num_attempts*num_messages} messages
        {num_true_positives} correctly verified
        {num_false_negatives} incorrectly dismissed
        {num_true_negatives} correctly dismissed
        {num_false_positives} incorrectly verified
        {num_passed_true_proofs} correctly validated proofs
        {num_failed_false_proofs} correctly dismissed proofs""")

    assert(num_false_positives == 0)
    assert(num_false_negatives == 0)
    assert(num_passed_true_proofs == num_failed_false_proofs)

    return channel

def user_join_sequence():
    messages = [123,124,124152,11,1231,513]
    disclosedMessages = []
    params = BBS.TrustedPublicAuthority.GGen()
    channel = BBS.InsecureChannel()
    user = BBS.User(params)
    gm = BBS.GM(params)
    sig = channel.user_sign(user, gm, messages)
    val = channel.partial_disclosure_proof(user, gm, sig, messages, disclosedMessages)
    # print(channel.leaked_data)
    print("special case", val)
    

def fixed_value_test():
    pass



if __name__ == "__main__":
    test_message_signing(num_attempts=num_attempts, num_messages=num_messages)
    user_join_sequence()