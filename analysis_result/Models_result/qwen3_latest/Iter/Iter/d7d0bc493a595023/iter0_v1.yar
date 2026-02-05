rule ExitFunctionSignatures
{
    meta:
        description = "Detects the use of exit functions in a potential malicious context."
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $pattern0 = "FF7508 E8 ?? ?? ?? ??"
        $pattern1 = "FF15 ?? ?? ?? ??"
        $pattern2 = "55 8BEC FF7508 E8 ?? ?? ?? ??"

    condition:
        any of them
}