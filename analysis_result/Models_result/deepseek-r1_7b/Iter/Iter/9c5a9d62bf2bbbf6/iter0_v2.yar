rule Evasion_Bypass_Patterns
{
    meta:
        description = "Evasion bypass detection based on call dword ptr [0041B0ACh]"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { ?? ?? FF 50 8B EC FF FF ?? ?? FF 50 }
}

# When the target pattern is found, skip the call to dword ptr [0041B0ACh]