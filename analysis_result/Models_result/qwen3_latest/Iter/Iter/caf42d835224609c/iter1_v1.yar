rule EvasionCheck
{
    meta:
        description = "Evasion check pattern for sample caf42d835224609c"
        author = "YourName"
        date = "2025-03-20"
        cape_options = {
            "pattern0": "E8 54 D3 FF FF 8D 85 4C F2 FF FF",
            "pattern1": "E8 72 E5 FF FF 8B 85 4C F2 FF FF",
            "pattern2": "E8 E7 E9 FF FF 8B D0"
        }

    condition:
        any of them
}