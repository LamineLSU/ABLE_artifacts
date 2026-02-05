rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = {
            "pattern0": "pattern0",
            "pattern1": "pattern1",
            "pattern2": "pattern2"
        }
    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $pattern2 = { C1 E8 08 A8 01 75 10 }
    condition:
        any of them
}