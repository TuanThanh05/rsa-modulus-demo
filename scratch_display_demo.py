from src.common_modulus_attack import common_modulus_attack
from src.display import print_attack_trace
from src.display import print_final_result


n = 247
e1 = 5
e2 = 7
c1 = 140
c2 = 30
original_m = 30

recovered_m, trace = common_modulus_attack(c1, c2, e1, e2, n)

print_attack_trace(trace)

print_final_result(
    original_message_int=original_m,
    recovered_message_int=recovered_m,
)