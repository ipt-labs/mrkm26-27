
import random

seed = 42
n = 10

random.seed(seed)
sequence1 = [random.randint(0, 255) for _ in range(n)]

random.seed(seed)
sequence2 = [random.randint(0, 255) for _ in range(n)]

print("I try:", sequence1)
print("II try:", sequence2)
print("Same?", sequence1 == sequence2)
