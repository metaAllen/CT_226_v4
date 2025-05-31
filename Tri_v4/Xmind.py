def classify_activity(activity: str, time: float, done: float):
    """
    Classifies an individual based on their activity, time, and completion percentage.

    Args:
        activity (str): The activity type (e.g., Swim, Bike, Run).
        time (float): Time spent on the activity (in hours).
        done (float): Completion percentage (0-100).

    Returns:
        str: The group the individual belongs to (e.g., A_Group, B_Group, etc.).
    """
    if activity == "Swim" or activity == "Bike" or activity == "Run":
        if time == 1.5:
            if done >= 90:
                return "A_Group"
            elif 75 <= done < 90:
                return "B_Group"
        elif time == 1.0:
            if 50 <= done < 75:
                return "B_Group"
        elif time == 0.5:
            if 25 <= done < 50:
                return "D_Group"
            elif done < 25:
                return "E_Group"
    return "No Group"

# Example usage
if __name__ == "__main__":
    # Test cases
    test_cases = [
        ("Swim", 1.5, 95),  # A_Group
        ("Bike", 1.5, 80),  # B_Group
        ("Run", 1.0, 60),   # B_Group
        ("Swim", 0.5, 30),  # D_Group
        ("Bike", 0.5, 20),  # E_Group
        ("Run", 2.0, 50),   # No Group
    ]

    for activity, time, done in test_cases:
        group = classify_activity(activity, time, done)
        print(f"Activity: {activity}, Time: {time} hrs, Done: {done}% -> Group: {group}")
