rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 40 40 00 E8 90 F6 FF FF 8B D8 83 C4 04 85 DB 74 1B 90 8B 45 08 50 53 E8 EC F4 FF FF 83 C4 08 85 C0 75 0E 53 E8 6B F3 FF FF 5F 5E 5B 5D }
        $pattern1 = { 74 07 50 FF 15 50 B0 AB 00 FF 74 24 10 FF 15 D8 90 AB 00 FF 74 24 14 FF 15 B8 90 AB 00 EB 19 8B 0D C0 83 AB 00 68 BC 18 AB 00 FF 74 24 10 E8 E0 FB FF FF 8B 7C 24 2C 83 FF FF 74 1A 83 7C 24 18 00 74 0C FF 74 24 18 6A 00 FF 15 34 91 AB 00 FF 15 38 91 AB 00 85 F6 74 07 56 FF 15 D8 90 AB 00 33 FF 53 FF 15 B8 90 AB 00 83 3D BC 83 AB 00 01 75 06 FF 15 44 90 AB 00 57 FF 15 38 91 AB 00 }
        $pattern2 = { 85 DB 74 1B 90 8B 45 08 50 53 E8 EC F4 FF FF 83 C4 08 85 C0 75 0E 53 E8 6B F3 FF FF 5F 5E 5B 5D }

    condition:
        any of them
}