rule Bypass_Evasion
{
    meta:
        description = "Bypass multiple evasion exits by skipping critical jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 ?? FF 75 08 8B FF 55 8B EC ?? ?? ?? ?? 83 F8 }
        $pattern2 = { E8 4B 17 00 00 00 C9 00 00 00 00 00 FF E1 05 B5 }

    condition:
        any of them
}