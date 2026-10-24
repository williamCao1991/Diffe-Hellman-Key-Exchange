def modular_exponentiation(base, exponent, modulus):
    """
    Function to calculate base by exponent while modulus wihtout using the full computing power to iterate through the exponent.
    
    Args: 
    base (int): The base number.
    exponent (int): The exponent number.
    modulus (int): The modulus number.
    
    Returns:
    Int: Result of (base ** exponent ) modulus
    """
    try:
        if modulus <= 0 or exponent < 0:
            raise ValueError("Modulus or exponent must be a positive integer.")
    except ValueError as e:
        print(e)
        return "Reject"
    
    result = 1 % modulus
    base = base % modulus

    while exponent > 0:
        if exponent % 2 ==1:
            result = (result * base) % modulus
        exponent = exponent // 2
        base = (base * base) % modulus
    return result




x = modular_exponentiation(2, 10, 1000)
x1 = modular_exponentiation(3, 5, -13)
print(x)
print(x1)




            
