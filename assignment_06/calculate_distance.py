import sys


def word_level_edit_distance(file1_path, file2_path):
    """
    Calculates the Levenshtein distance between the word lists of two files.
    """
    try:
        with open(file1_path, 'r') as f1:
            # Read content and split into words
            words1 = f1.read().split()
        with open(file2_path, 'r') as f2:
            words2 = f2.read().split()
    except FileNotFoundError as e:
        # Silently fail if a file doesn't exist (e.g., failed run)
        # Return a very high distance to indicate failure.
        return 9999

    # Get the number of words in each list
    m, n = len(words1), len(words2)

    # Initialize a DP table (matrix) with zeros
    # dp[i][j] will be the distance between the first i words of words1
    # and the first j words of words2.
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    # Initialize the first row and column of the DP table
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    # Fill the rest of the DP table
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if words1[i - 1] == words2[j - 1] else 1

            # The distance is the minimum of deletion, insertion, or substitution
            dp[i][j] = min(dp[i - 1][j] + 1,        # Deletion
                           dp[i][j - 1] + 1,        # Insertion
                           dp[i - 1][j - 1] + cost)  # Substitution

    # The final distance is in the bottom-right cell
    return dp[m][n]


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 calculate_distance.py <file1> <file2>", file=sys.stderr)
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]

    distance = word_level_edit_distance(file1, file2)
    print(distance)
