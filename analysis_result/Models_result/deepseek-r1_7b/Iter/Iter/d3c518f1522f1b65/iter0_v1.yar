rule Bypass_Evasion
{
    meta:
        description = "Memory Evasion Bypass Patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 74 5B FF 75 08 6A ?? 5A 8B CE E8 ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 00 FA 61 2C 6E 33 F3 9C EB 87 8D FF 0F 84 74 1B 00 FF 15 AC B0 41 00 ?? }
        $pattern2 = { 85 C0 0F 84 6A 5B 8B CE E8 FF 15 F0 FF 8C 8F FF FF FF FF FF FF }

    condition:
        any of them
}