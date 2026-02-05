rule {
    ($pattern0 | $pattern1 | $pattern2);

    // Pattern 0: Includes push ebp and mov ebp, esp
    $pattern0 = 558BEC; 

    // Pattern 1: Extends to include more bytes
    $pattern1 = E8C47539;

    // Pattern 2: Includes FF7508 followed by pop ecx
    $pattern2 = FF750859;
}