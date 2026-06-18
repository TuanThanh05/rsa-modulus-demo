def validate_attack_inputs(c1, c2, e1, e2, n):
    values = {"c1": c1, "c2": c2, "e1": e1, "e2": e2, "n": n}
    for name, value in values.items():
        if not isinstance(value, int):
            raise TypeError(f"{name} phải có kiểu int")
    if n <= 1:
        raise ValueError("n phải là số nguyên lớn hơn 1")

    if e1 <= 1:
        raise ValueError("e1 phải là số nguyên lớn hơn 1")

    if e2 <= 1:
        raise ValueError("e2 phải là số nguyên lớn hơn 1")

    if e1 == e2:
        raise ValueError("e1 và e2 phải khác nhau")

    if not (0 <= c1 < n):
        raise ValueError("c1 phải thỏa 0 <= c1 < n")

    if not (0 <= c2 < n):
        raise ValueError("c2 phải thỏa 0 <= c2 < n")
    