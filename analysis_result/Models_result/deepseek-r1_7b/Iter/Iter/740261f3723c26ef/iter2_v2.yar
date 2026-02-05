rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+01,action0=skip,bp1=$pattern1+01,action1=skip,bp2=$pattern2+01,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // Skips mov edi, edi
        $pattern1 = { E8 C8 FF FF FF 00 83 C4 ?? ?? ?? ?? ?? }    // Skips push ebp
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 83 C4 ?? }  // Skips mov ebp, esp

    condition:
        any of them
}